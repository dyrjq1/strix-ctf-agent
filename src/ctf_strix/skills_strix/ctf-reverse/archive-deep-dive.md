# ctf-reverse — deep-dive archive

> Moved verbatim from the index under the 8KB gate. Read with `exec_command` (`cat` / `sed -n`); reference notes, not a skill — do NOT `load_skill`.

## Additional Resources

- [unicorn-emulation.md](unicorn-emulation.md) - Unicorn CPU emulation: raw binary assembly emulation, hooks, ARM/MIPS/Thumb, mixed-mode, firmware MMIO, Keystone+Capstone trace inversion, shellcode unpack, custom VM, vs Qiling decision (sometimes easier to rev with just unicorn + binary + assembly than full GDB/angr)
- [tools.md](tools.md) - Static analysis tools (GDB, Ghidra, radare2, IDA, Binary Ninja, dogbolt.org, RISC-V with Capstone, Unicorn emulation, Python bytecode, WASM, Android APK, .NET, packed binaries)
- [radare2-r2pipe.md](radare2-r2pipe.md) - radare2 scripting deep dive (batch mode without an interactive shell, `wx` byte patching in batch mode, r2ghidra decompilation with `pdg`/`pdgj` plus plugin ABI matching, ESIL single-function emulation with `aei`/`aeim`/`aesu`, r2pipe session lifecycle and `cmdj` JSON traps, mapping checkers with xrefs and `aflj`)
- [tools-mcp.md](tools-mcp.md) - MCP server integration (agent-driven RE): IDA Pro MCP (GUI plugin + idalib headless), Ghidra MCP (headless server, no GUI), JADX MCP (Android APK/DEX), plus crossing the JNI boundary by `dlopen`-ing an Android `.so` on the host instead of decompiling it
- [tools-dynamic.md](tools-dynamic.md) - Dynamic analysis tools: Frida (hooking, anti-debug bypass, memory scanning, Android/iOS), angr symbolic execution (path exploration, constraints, CFG), lldb (macOS/LLVM debugger), x64dbg (Windows) -- none of these are installed in this image; human-side references only.
- [tools-emulation.md](tools-emulation.md) - Emulation frameworks and side-channel tooling: Qiling (cross-platform OS-level emulation), Triton (DSE), Intel Pin instruction-counting + genetic algorithm side channel, opcode-only trace reconstruction, LD_PRELOAD time freeze and memcmp side-channel for byte-by-byte bruteforce -- Qiling and Triton are not installed in this image.
- [tools-advanced.md](tools-advanced.md) - Advanced tools (Part 1): VMProtect/Themida analysis, binary diffing (BinDiff, Diaphora), deobfuscation frameworks (D-810, GOOMBA, Miasm), Qiling framework, Triton DSE, Manticore, Rizin/Cutter, RetDec, custom VM bytecode lifting to LLVM IR -- none of these ship in the image.
- [tools-advanced-2.md](tools-advanced-2.md) - Advanced tools (Part 2): advanced GDB (Python scripting, brute-force, conditional breakpoints, watchpoints, reverse debugging with rr, pwndbg/GEF), advanced Ghidra scripting, patching (Binary Ninja API, LIEF), GDB constraint extraction + ILP solver (BackdoorCTF 2017), GDB position-encoded input zero flag monitoring (EKOPARTY 2017), LD_PRELOAD execute-only binary dump (BackdoorCTF 2017), PEDA current_inst bit-by-bit flag scraper (CONFidence CTF 2019 Teaser)
- [mba-simplification.md](mba-simplification.md) - MBA simplification with msynth: oracle-backed Simplifier vs from-scratch Synthesizer search, mandatory random-input equivalence check, Miasm integration
- [anti-analysis.md](anti-analysis.md) - Anti-analysis taxonomy: Linux anti-debug (ptrace, /proc, timing, signals, direct syscalls), Windows anti-debug (PEB, NtQueryInformationProcess, heap flags, TLS callbacks, HW/SW breakpoint detection, exception-based, thread hiding), anti-VM/sandbox (CPUID, MAC, timing, artifacts, resources), anti-DBI (Frida detection/bypass), code integrity/self-hashing, anti-disassembly (opaque predicates, junk bytes), MBA identification/simplification, comprehensive bypass strategies
- [anti-analysis-ctf.md](anti-analysis-ctf.md) - CTF writeup techniques: SIGILL handler for execution mode switching (Hack.lu 2015), SIGFPE signal handler side-channel via strace counting (PlaidCTF 2017), instruction trace inversion with Keystone and Unicorn (MeePwn 2017), call-less function chaining via stack frame manipulation (THC 2018), parent-patched child binary dump via `process_vm_writev` (Google CTF Quals 2018)
- [patterns.md](patterns.md) - Foundational binary patterns: custom VMs, anti-debugging, nanomites, self-modifying code, XOR ciphers, mixed-mode stagers, LLVM obfuscation, S-box/keystream, SECCOMP/BPF, exception handlers, memory dumps, byte-wise transforms, x86-64 gotchas, custom mangle reversing, position-based transforms, hex-encoded string comparison, signal-based binary exploration
- [patterns-runtime.md](patterns-runtime.md) - Runtime patching and oracle techniques: malware anti-analysis bypass, multi-stage shellcode loaders, timing side-channel attacks, multi-thread anti-debug with decoy + signal handler MBA (ApoorvCTF 2026), INT3 patch + coredump brute-force oracle (Pwn2Win 2016), signal handler chain + LD_PRELOAD oracle (Nuit du Hack 2016), printf format string VM decompilation to Z3 (SECCON 2017), quadtree recursive image format parser (Google CTF Quals 2018)
- [patterns-ctf.md](patterns-ctf.md) - Competition-specific patterns (Part 1): hidden emulator opcodes, LD_PRELOAD key extraction, SPN static extraction, image XOR smoothness, byte-at-a-time cipher, mathematical convergence bitmap, Windows PE XOR bitmap OCR, two-stage RC4+VM loaders, GBA ROM meet-in-the-middle, Sprague-Grundy game theory, kernel module maze solving, multi-threaded VM channels, backdoored shared library detection via string diffing, custom binfmt kernel module with RC4 flat binaries, hash-resolved imports / no-import ransomware, ELF section header corruption for anti-analysis
- [patterns-ctf-2.md](patterns-ctf-2.md) - Competition-specific patterns (Part 2): multi-layer self-decrypting brute-force, embedded ZIP+XOR license, stack string deobfuscation, prefix hash brute-force, CVP/LLL lattice for integer validation, decision tree function obfuscation, GF(2^8) Gaussian elimination, ROP chain obfuscation analysis (ROPfuscation)
- [patterns-ctf-3.md](patterns-ctf-3.md) - Competition-specific patterns (Part 3): Z3 single-line Python circuit, sliding window popcount, keyboard LED Morse code via ioctl, C++ destructor-hidden validation, syscall side-effect memory corruption, MFC dialog event handlers, VM sequential key-chain brute-force, Burrows-Wheeler transform inversion, OpenType font ligature exploitation, GLSL shader VM with self-modifying code, instruction counter as cryptographic state, batch crackme automation via objdump, fork+pipe+dead branch anti-analysis, TensorFlow DNN inversion via sigmoid layer inversion, BPF filter analysis via kernel JIT to x64 assembly
- [languages.md](languages.md) - Language-specific: Python bytecode & opcode remapping, Python version-specific bytecode, Pyarmor static unpack, DOS stubs, Unity IL2CPP, HarmonyOS HAP/ABC, Brainfuck/esolangs (+ BF character-by-character static analysis, BF side-channel read count oracle, BF comparison idiom detection), UEFI, transpilation to C, code coverage side-channel, OPAL functional reversing, non-bijective substitution, FRACTRAN program inversion
- [languages-platforms.md](languages-platforms.md) - Platform/framework-specific: Roblox place file analysis, Godot game asset extraction, Rust serde_json schema recovery, Android JNI RegisterNatives obfuscation, Android DEX runtime bytecode patching via /proc/self/maps, Android native .so loading bypass via new project, Frida Firebase Cloud Functions bypass, Verilog/hardware RE, prefix-by-prefix hash reversal, Ruby/Perl polyglot constraint satisfaction, Electron ASAR extraction + native binary analysis, Node.js npm runtime introspection
- [languages-compiled.md](languages-compiled.md) - Go binary reversing (GoReSym, goroutines, memory layout, channel ops, embed.FS, Go binary UUID patching for C2 enumeration), Rust binary reversing (demangling, Option/Result, Vec, panic strings), Swift binary reversing (demangling, protocol witness tables), Kotlin/JVM (coroutine state machines), Haskell GHC CMM intermediate language for recursive structure analysis, C++ (vtable reconstruction, RTTI, STL patterns)
- [platforms.md](platforms.md) - Platform-specific RE: macOS/iOS (Mach-O, code signing, Objective-C runtime, Swift, dyld, jailbreak bypass), embedded/IoT firmware (binwalk, UART/JTAG/SPI extraction, ARM/MIPS, RTOS), kernel drivers (Linux .ko, eBPF, Windows .sys), game engines (Unreal Engine, Unity, anti-cheat, Lua), automotive CAN bus
- [platforms-hardware.md](platforms-hardware.md) - Hardware and advanced architecture RE: HD44780 LCD controller GPIO reconstruction, RISC-V advanced (custom extensions, privileged modes, debugging), ARM64/AArch64 reversing and exploitation (calling convention, ROP gadgets, qemu-aarch64-static emulation)
- [field-notes.md](field-notes.md) - Quick reference notes: binary types, anti-debugging bypass, specialized patterns, CTF case notes

---

## Initial Analysis

```bash
file binary           # Type, architecture
checksec --file=binary # Security features (for pwn)
chmod +x binary       # Make executable
```

## Memory Dumping Strategy

**Key insight:** Let the program compute the answer, then dump it. Break at final comparison (`b *main+OFFSET`), enter any input of correct length, then `x/s $rsi` to dump computed flag.

## Decoy Flag Detection

**Pattern:** Multiple fake targets before real check. Look for multiple comparison targets in sequence with different success messages. Set breakpoint at FINAL comparison, not earlier ones.

## Deep-Dive Notes

Use [field-notes.md](field-notes.md) after the first round of triage when you know what kind of target you have.

- Target formats: Python bytecode, WASM, Android, Flutter, .NET, UPX, Tauri
- Technique notes: anti-debug bypass, VM analysis, x86-64 gotchas, iterative solvers, Unicorn, timing side channels
- Platform notes: Godot, Roblox, macOS/iOS, embedded firmware, kernel drivers, game engines, Swift, Kotlin, Go, Rust, D
- Case notes: modern CTF-specific reversing patterns and older classic challenge patterns
