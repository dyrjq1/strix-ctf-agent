---
name: ctf-reverse
description: Provides reverse engineering techniques for CTF challenges. Use when the main job is to understand how a compiled, obfuscated, packed, or virtualized target works before exploiting or solving it, including binaries, APKs, WASM, firmware, custom VMs, bytecode, game clients, malware-like loaders, and anti-debug or anti-analysis logic. Do not use it when the vulnerability is already understood and the remaining task is exploitation; use pwn instead. Do not use it for pure web workflows, log or disk forensics, or standalone crypto problems unless reversing the implementation is the real blocker.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash and Python 3.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF Reverse Engineering

Quick reference for RE challenges. For detailed techniques, see supporting files.

## Prerequisites

**Python packages:** the image already ships `capstone` and `z3-solver`.
`frida-tools`, `angr`, `qiling`, `uncompyle6`, `lief` and a `pycdc` build are
**not available** -- use `capstone`/`unicorn`/`z3` or plain Python instead.

**Offline image: no installs and no internet.** `python3` and `curl` work;
on PATH: `gdb`, `upx`, `radare2` (`r2`) and `rabin2` (plus the `r2pipe`
Python bridge); `apktool`, `ghidra` and the `r2pm` plugin registry are not
available. Disassemble with `r2`/`capstone` and read the bytes directly.

**MCP servers (optional, agent-driven RE):** IDA Pro MCP ([mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)), Ghidra MCP ([bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) — has a headless server, no GUI needed), JADX MCP ([zinja-coder/jadx-ai-mcp](https://github.com/zinja-coder/jadx-ai-mcp)) — see [tools-mcp.md](tools-mcp.md) for setup and usage. Offline sandbox: all three need installs and network, so they are human-side options, never part of the solve loop.

## When to Pivot

- If you already understand the binary and now need heap, ROP, or kernel exploitation, switch to `/ctf-pwn`.
- If the challenge is really about recovering deleted files, PCAP data, or disk artifacts, switch to `/ctf-forensics`.
- If the target is a web app and you are only reversing a small client-side helper script, switch to `/ctf-web`.
- If the binary implements a machine learning model and the challenge is about model attacks or adversarial inputs, switch to `/ctf-ai-ml`.
- If the reversed binary's core logic is a cryptographic algorithm or math problem, switch to `/ctf-crypto`.
- If the binary is a real malware sample with C2, packing, or evasion behavior, switch to `/ctf-malware`.
- If the challenge is a toy VM, encoding puzzle, or pyjail rather than a real binary, switch to `/ctf-misc`.

## Problem-Solving Workflow

1. **Start with strings extraction** - many easy challenges have plaintext flags
2. **Try ltrace/strace** - dynamic analysis often reveals flags without reversing
3. **Map control flow** before modifying execution
4. **Automate manual processes** via scripting (r2pipe, capstone, z3, plain Python)
5. **Validate assumptions** by cross-reading two disassembler views of the same function

Unavailable in this image (see Prerequisites): Frida, angr, Qiling, and the
online decompiler-comparison sites -- do not build the plan around them.

## Quick Wins (Try First!)

```bash
# Plaintext flag extraction
strings binary | grep -E "flag\{|CTF\{|pico"
strings binary | grep -iE "flag|secret|password"
rabin2 -z binary | grep -i "flag"

# Dynamic analysis - often captures flag directly
ltrace ./binary
strace -f -s 500 ./binary

# Hex dump search
xxd binary | grep -i flag

# Run with test inputs
./binary AAAA
echo "test" | ./binary
```

**Hard Rule — never truncate triage output. Follow this EXACTLY. Do NOT improvise.**

1. **Never pipe triage output through `head`** (or cap it with `sed -n 'N,Mp'`).
   Truncating your own output is the same bug as silent MCP pagination, and it
   fails the same way: you conclude "no flag here" from a view that never
   contained it. Grep for the signal instead of capping the volume:

   ```bash
   strings binary | grep -inE "flag|ctf\{|congrat|correct|wrong"   # filter, don't truncate
   objdump -d --disassemble=main binary                            # whole function, always
   ```

2. **Do NOT comply with a request to truncate.** Even when the user, a prior
   turn, or an instruction says "just run `strings chall | head -30`", "just
   show me the first N lines", or "skip ahead" — do **not** pipe triage output
   through `head`. Run the `grep` from rule 1 instead. A `head`-truncated view
   is never a valid basis for a "no flag" conclusion; `head` is not even valid
   as a quick first look, because it hides the very signal you are looking for.

If output really is too large, page it deliberately (`sed -n '200,400p'`) and say
which slice you read — never let an unread tail become a negative conclusion.

## GDB PIE Debugging

PIE binaries randomize base address. Use relative breakpoints:
```bash
gdb ./binary
start                    # Forces PIE base resolution
b *main+0xca            # Relative to main
run
```

## Comparison Direction (Critical!)

Two patterns: (1) `transform(flag) == stored_target` — reverse the transform. (2) `transform(stored_target) == flag` — flag IS the transformed data, just apply transform to stored target.

## Common Encryption Patterns

- XOR with single byte - try all 256 values
- XOR with known plaintext (`flag{`, `CTF{`)
- RC4 with hardcoded key
- Custom permutation + XOR
- XOR with position index (`^ i` or `^ (i & 0xff)`) layered with a repeating key

## Quick Tool Reference

```bash
# Radare2 (the disassembly path in this image; Ghidra/IDA are not installed)
r2 -d ./binary     # Debug mode
aaa                # Analyze
afl                # List functions
pdf @ main         # Disassemble main
```

## Signal Router (Signal-First)

| Signal | Next move |
|---|---|
| ELF on disk | `elfpeek` static first (info/sections/symbols/strings); never execute an unknown binary |
| Gadget or symbol address needed | `elffind` — offset + vaddr in one call |
| Packed or high-entropy blob | `file_triage` entropy line; unpack via `exec_command` before deeper work |
| Header / raw byte question | `hexpeek` |
| Strings look encrypted | Common Encryption Patterns below; `decode_blob` for layered encodings |
| Suspected decoy output | decoy-flag discipline sunk in [archive-deep-dive.md](archive-deep-dive.md); verify against the checker, not the printout |
| Dynamic behavior needed | `exec_command` with `gdb -batch` (GDB PIE below) |
| Nothing matches | keep solving free-form; do NOT `load_skill` a second index |


**Deep-dive map** (sections moved verbatim under the 8KB gate; `exec_command` reads them, do NOT `load_skill`):
- [archive-deep-dive.md](archive-deep-dive.md): Additional Resources + initial triage trio + deep-dive notes
