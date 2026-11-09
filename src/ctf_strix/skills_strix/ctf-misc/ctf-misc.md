---
name: ctf-misc
description: Provides miscellaneous CTF challenge techniques for problems that do not cleanly fit the main categories. Use for encoding puzzles, pyjails, bash jails, RF/SDR, DNS oddities, unicode tricks, esoteric languages, QR or audio puzzles, constraint solving, game theory, unusual sandbox escapes, and hybrid logic puzzles. Prefer a more specific skill first when the challenge is mainly web, pwn, reverse, forensics, malware, OSINT, or crypto. Treat this as the fallback skill for genuine cross-category or edge-case challenges, not the default starting point.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash and Python 3.
allowed-tools: Bash Read Write Edit Glob Grep Task Skill
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF Miscellaneous

Quick reference for miscellaneous CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Prerequisites

**Python packages:** the image already ships `pwntools` 4.15.0, `segno`
1.6.6, `z3-solver`, `Pillow`, `numpy`, `matplotlib`, `requests`, `dnslib`,
`scapy`, `reedsolo`, and `r2pipe` -- nothing to install.

**Offline image: no installs and no internet.** `python3` and `curl` work; on
PATH: `7z`, `binwalk`, `zbarimg` (QR/barcode decode), `sox`, `pngcheck` and
`upx`; `ffmpeg`, `qrencode` and SageMath are not available -- generate QR
with `segno`, decode with `zbarimg`, and handle audio with `sox` + `numpy`.

## When to Pivot

- If the puzzle is actually centered on cryptography or number theory, switch to `/ctf-crypto`.
- If the challenge is a real binary exploit instead of a jail, toy VM, or encoding problem, switch to `/ctf-pwn` or `/ctf-reverse`.
- If the input is mostly files, images, audio, or packet captures that need recovery work first, switch to `/ctf-forensics`.
- For ML/AI techniques (model attacks, adversarial examples, LLM jailbreaking), see `/ctf-ai-ml`.
- If the NodeJS sandbox uses **vm2** (`npm ls vm2`), check for **CVE-2023-37466** via `Promise[@@species]` with `nesting:true` — the exception handler escapes the context; see `ctf-web/js-sandbox` for the full exploit chain. In misc challenges with bundled JS, always run `npm ls vm2` to detect vulnerable vm2 before trying other escapes.

## Quick Start Commands

```bash
# File identification
file mystery_file
xxd mystery_file | head -5
python3 -c "import magic; print(magic.from_file('mystery_file'))"

# Encoding detection
python3 -c "import base64; print(base64.b64decode('<data>'))"
echo '<data>' | base64 -d
echo '<hex>' | xxd -r -p

# QR code
zbarimg qr.png
python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('qr.png')))"

# Z3 constraint solving
python3 -c "from z3 import *; x=BitVec('x',32); s=Solver(); s.add(x^0xdead==0xbeef); s.check(); print(s.model())"

# Python jail test
python3 -c "__import__('os').system('id')"
```

## General Tips

- Read all provided files carefully
- Check file metadata, hidden content, encoding
- Power Automate scripts may hide API calls
- Use binary search when guessing multiple answers

## Common Encodings

```bash
# Base64
echo "encoded" | base64 -d

# Base32 (A-Z2-7=)
echo "OBUWG32D..." | base32 -d

# Hex
echo "68656c6c6f" | xxd -r -p

# ROT13
echo "uryyb" | tr 'a-zA-Z' 'n-za-mN-ZA-M'
```

**Identify by charset:**
- Base64: `A-Za-z0-9+/=`
- Base32: `A-Z2-7=` (no lowercase)
- Hex: `0-9a-fA-F`

See [encodings.md](encodings.md) for Caesar brute force, URL encoding, and full details.

## Python Jail Quick Reference

- **Oracle pattern:** `L()` = length, `Q(i,x)` = compare, `S(guess)` = submit. Linear or binary search.
- **Walrus bypass:** `(abcdef := "new_chars")` reassigns constraint vars
- **Decorator bypass:** `@__import__` + `@func.__class__.__dict__[__name__.__name__].__get__` for no-call, no-quotes escape
- **String join:** `open(''.join(['fl','ag.txt'])).read()` when `+` is blocked

See [pyjails.md](pyjails.md) for full techniques.

## Z3 / Constraint Solving

```python
from z3 import *
flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()
# Add constraints, check sat, extract model
```

See [games-and-vms.md](games-and-vms.md) for YARA rules, type systems as constraints, boolean logic gate network SAT solving.

## Hash Identification

MD5: `0x67452301` | SHA-256: `0x6a09e667` | MurmurHash64A: `0xC6A4A7935BD1E995`

## CTFd Platform Navigation (No Browser)

Detect CTFd (`curl -s "$CTF_URL/api/v1/" | head -5`) and interact via API. **Ask the user for their API token** (CTFd Settings > Access Tokens) — it is not provided by default. Then use `Authorization: Token $CTF_TOKEN` header for all requests.

```bash
export CTF_URL="https://ctf.example.com" CTF_TOKEN="ctfd_your_token_here"
curl -s -H "Authorization: Token $CTF_TOKEN" "$CTF_URL/api/v1/challenges" | jq -r '.data[] | "\(.id)\t\(.value)pts\t\(.category)\t\(.name)"'
curl -s -X POST -H "Authorization: Token $CTF_TOKEN" -H "Content-Type: application/json" "$CTF_URL/api/v1/challenges/attempt" -d "{\"challenge_id\": $CID, \"submission\": \"flag{...}\"}"
```

See [ctfd-navigation.md](ctfd-navigation.md) for full workflow, Python client class, session login, hints, notifications, file download, and troubleshooting.

---

## Useful One-Liners

```bash
grep -rn "flag{" .
strings file | grep -i flag
python3 -c "print(int('deadbeef', 16))"
```

## Backdoor Detection in Source Code

**Pattern (Rear Hatch):** Hidden command prefix triggers `system()` call.

**Common patterns:**
- `strncmp(input, "exec:", 5)` -> runs `system(input + 5)`
- Hex-encoded comparison strings: `\x65\x78\x65\x63\x3a` = "exec:"
- Hidden conditions in maintenance/admin functions

## Cipher Identification Workflow

1. **ROT13** - Challenge mentions "ROT", text looks like garbled English
2. **Base64** - `A-Za-z0-9+/=`, title hints "64"
3. **Base32** - `A-Z2-7=` uppercase only
4. **Atbash** - Title hints (Abash/Atbash), preserves spaces, 1:1 substitution
5. **Pigpen** - Geometric symbols on grid
6. **Keyboard Shift** - Text looks like adjacent keys pressed
7. **Substitution** - Frequency analysis applicable

**Auto-identify:** [dCode Cipher Identifier](https://www.dcode.fr/cipher-identifier)

## Signal Router (Signal-First)

Read the artifact before choosing a technique; match the signal, not a technique name:

| Signal | Next move |
|---|---|
| Encoded string, possibly layered | `decode_blob` — one call reports the whole chain that worked |
| Unknown file or directory | `file_triage` — family, entropy, and its "one command to run next" line |
| Archive, possibly nested | `unpack_archive` — safe extraction that recurses into inner archives |
| Raw bytes / magic bytes | `hexpeek` before any parser; header truth first |
| QR / image / audio / RF artifact | `view_image` or `exec_command`; section notes live in [archive-deep-dive.md](archive-deep-dive.md) |
| Python jail / restricted shell | Python Jail Quick Reference below, then `exec_command` python probes |
| Cipher-like text | Cipher Identification Workflow below; automate with python, never brute-guess |
| Hash-like string | Hash Identification below, then an offline wordlist run |
| Jail, privesc or backdoor hint | Backdoor Detection below; priv-esc checklists sunk into [archive-deep-dive.md](archive-deep-dive.md) |
| Nothing matches | keep solving free-form; do NOT `load_skill` a second index |


**Deep-dive map** (sections moved verbatim under the 8KB gate; `exec_command` reads them, do NOT `load_skill`):
- [archive-deep-dive.md](archive-deep-dive.md): Additional Resources + encoding/audio/QR/RF/privesc/pwntools notes + contest-style technique notes
