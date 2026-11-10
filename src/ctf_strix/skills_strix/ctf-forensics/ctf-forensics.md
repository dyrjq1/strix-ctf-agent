---
name: ctf-forensics
description: Provides digital forensics and signal analysis techniques for CTF challenges. Use when analyzing disk images, memory dumps, event logs, network captures, cryptocurrency transactions, steganography, PDF analysis, Windows registry, Volatility, PCAP, Docker images, coredumps, side-channel power traces, DTMF audio spectrograms, packet timing analysis, CD audio disc images, or recovering deleted files and credentials.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash and Python 3.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF Forensics & Blockchain

Quick reference for forensics CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Prerequisites

**Python packages:** the image already ships `Pillow`, `numpy`, `matplotlib`,
`scipy`, and the `impacket` CLI set (`secretsdump.py`, `wmiexec.py`,
`psexec.py`, ...). `volatility3`, `librosa`, `scikit-learn`,
`opencv-python-headless`, `pymongo`, `brotli`, `exrex`, `stegano`, and
`heatshrink2` are **not available** -- use the installed libraries or plain
Python instead.

**Offline image: no installs and no internet.** `python3` ships `Pillow`,
`numpy`, `scipy`, `matplotlib`, `scapy` and `reedsolo`, and `curl` works. On
PATH: `binwalk`, `exiftool`, `7z`, `upx`, `zbarimg`, `sox`, `pngcheck`,
`pdftotext`, `tcpdump`, `tshark`, `steghide`, Sleuth Kit (`fls`/`icat`/`mmls`)
and `radare2`/`rabin2`; still missing: `foremost`, `ffmpeg`, `testdisk`,
`john` and `zsteg` -- for those, carve and decode with the installed CLIs,
`strings`, and plain byte-level parsing.

## When to Pivot

- If you recover an encrypted blob and the hard part becomes RSA, AES, or lattice work, switch to `/ctf-crypto`.
- If the evidence really points to malware staging, beacon config extraction, or packed samples, switch to `/ctf-malware`.
- If the artifact is a web app backup or API dump and the remaining problem is application logic, switch to `/ctf-web`.
- If the forensic evidence is really an encoding puzzle, steganography trick, or esoteric format rather than true forensics, switch to `/ctf-misc`.
- If you need to trace infrastructure, attribute actors, or investigate public records from forensic findings, switch to `/ctf-osint`.
- If the recovered artifact is a compiled binary or firmware that needs disassembly and analysis, switch to `/ctf-reverse`.

## Quick Start Commands

```bash
# File analysis
file suspicious_file
exiftool suspicious_file     # Metadata
binwalk suspicious_file      # Embedded files
strings -n 8 suspicious_file
hexdump -C suspicious_file | head  # Check magic bytes

# Disk forensics
sudo mount -o loop,ro image.dd /mnt/evidence
fls -r image.dd              # List files; icat image.dd <inode> extracts one
```

Memory dumps: no `volatility3` in this image — carve with `strings` and
targeted byte scans. See [disk-and-memory.md](disk-and-memory.md) for VM
forensics, coredump analysis, and a Volatility plugin reference (reference
only: for environments that do ship it).

## Log Analysis

```bash
grep -iE "(flag|part|piece|fragment)" server.log     # Flag fragments
grep "FLAGPART" server.log | sed 's/.*FLAGPART: //' | uniq | tr -d '\n'  # Reconstruct
sort logfile.log | uniq -c | sort -rn | head         # Find anomalies
```

See [linux-forensics.md](linux-forensics.md) for Linux attack chain analysis and Docker image forensics.

## When Logs Are Cleared

If attacker cleared event logs, use these alternative sources:
1. **USN Journal ($J)** - File operations timeline (MFT ref, timestamps, reasons)
2. **SAM registry** - Account creation from key last_modified timestamps
3. **PowerShell history** - ConsoleHost_history.txt (USN DATA_EXTEND = command timing)
4. **Defender MPLog** - Separate log with threat detections and ASR events
5. **Prefetch** - Program execution evidence
6. **User profile creation** - First login time (profile dir in USN journal)

See [windows.md](windows.md) for detailed parsing code and anti-forensics detection checklist.

## PDF Analysis

```bash
exiftool document.pdf        # Metadata (often hides flags!)
pdftotext document.pdf -     # Extract text
strings document.pdf | grep -i flag
binwalk document.pdf         # Embedded files
```

**Advanced PDF stego:** six techniques -- invisible text separators, URI annotations with escaped braces, Wiener deconvolution on blurred images, vector rectangle QR codes, compressed object streams (`mutool clean -d`), document metadata fields. Competition notes in [archive-deep-dive.md](archive-deep-dive.md).

See [steganography.md](steganography.md) for full PDF steganography techniques and code.

## Disk / VM / Memory Forensics

```bash
# Disk images
sudo mount -o loop,ro image.dd /mnt/evidence
fls -r image.dd  # then icat image.dd <inode> to carve a deleted file

# VM images (OVA/VMDK)
tar -xvf machine.ova
7z x disk.vmdk -oextracted "Windows/System32/config/SAM" -r

# String carving
strings -a -n 6 memdump.bin | grep -E "FLAG|SSH_CLIENT|SESSION_KEY"

# Coredump
gdb -c core.dump  # info registers, x/100x $rsp, find "flag"
```

See [disk-and-memory.md](disk-and-memory.md) for full Volatility plugin reference, VM forensics, and VMware snapshots. See [disk-advanced.md](disk-advanced.md) for deleted partition recovery, ZFS forensics, and ransomware analysis.

## Windows Password Hashes

`impacket` is installed (`secretsdump.py -sam SAM -system SYSTEM local` dumps the
bootkey-derived NTLM hashes directly); `hashcat` is not, so try the candidate
wordlist with `hashlib` after the dump.

See [windows.md](windows.md) for SAM details and [network-advanced.md](network-advanced.md) for NTLMv2 cracking from PCAP.

## Bitcoin Tracing

- Offline sandbox: the mempool.space API is unreachable — decode the raw
  transaction hex and follow outputs by hand; the API is a human-side option
  only
- **Peel chain:** ALWAYS follow LARGER output; round amounts indicate peels

## Uncommon File Magic Bytes

| Magic | Format | Extension | Notes |
|-------|--------|-----------|-------|
| `OggS` | Ogg container | `.ogg` | Audio/video |
| `RIFF` | RIFF container | `.wav`,`.avi` | Check subformat |
| `%PDF` | PDF | `.pdf` | Check metadata & embedded objects |
| `GCDE` | PrusaSlicer binary G-code | `.g`, `.bgcode` | See 3d-printing.md |

## Common Flag Locations

- PDF metadata fields (Author, Title, Keywords)
- Image EXIF data
- Deleted files (Recycle Bin `$R` files)
- Registry values
- Browser history
- Log file fragments
- Memory strings

## Browser Forensics

- **Chrome/Edge:** Decrypt `Login Data` SQLite with AES-GCM using DPAPI master key
- **Firefox:** Query `places.sqlite` -- `SELECT url FROM moz_places WHERE url LIKE '%flag%'`

See [linux-forensics.md](linux-forensics.md) for full browser credential decryption code.

## HTTP Exfiltration in PCAP

**Quick path:** `tshark --export-objects http,/tmp/objects` extracts uploaded files instantly. Check for multipart POST uploads, unusual User-Agent strings, and exfiltrated files (images with flag text). See [network.md](network.md) and [archive-deep-dive.md](archive-deep-dive.md) for the competition walk-through.

## Common Encodings

```bash
echo "base64string" | base64 -d
echo "hexstring" | xxd -r -p
# ROT13: tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**ROT18:** ROT13 on letters + ROT5 on digits. Common final layer in multi-stage forensics. See [linux-forensics.md](linux-forensics.md) for implementation.

**Deep-dive map** (sections moved verbatim under the 8KB gate; `exec_command` reads them, do NOT `load_skill`):
- [archive-deep-dive.md](archive-deep-dive.md): Additional Resources + evtx, stego, WMI, network forensics QR, platform-specific notes
