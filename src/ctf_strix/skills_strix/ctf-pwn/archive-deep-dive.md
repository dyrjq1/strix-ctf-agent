# ctf-pwn — deep-dive archive

> Moved verbatim from the index under the 8KB gate. Read with `exec_command` (`cat` / `sed -n`); reference notes, not a skill — do NOT `load_skill`.

## Additional Resources

- [overflow-basics.md](overflow-basics.md) - Stack/global buffer overflow, ret2win, canary bypass, canary byte-by-byte brute force on forking servers, struct pointer overwrite, signed integer bypass, hidden gadgets, stride-based OOB read leak, parser stack overflow via unchecked memcpy length with callee-saved register restoration
- [rop-and-shellcode.md](rop-and-shellcode.md) - Core ROP chains (ret2libc, syscall ROP, rdx control, shell interaction), ret2csu, bad character XOR bypass, exotic x86 gadgets (BEXTR/XLAT/STOSB/PEXT), stack pivot via xchg rax,esp, sprintf() gadget chaining for bad character bypass, canary XOR epilogue as RDX zeroing gadget, stub_execveat syscall as execve alternative via read() return value
- [rop-advanced.md](rop-advanced.md) - Advanced ROP techniques: double stack pivot to BSS via leave;ret, SROP (Sigreturn-Oriented Programming) with UTF-8 constraints, seccomp bypass, RETF architecture switch (x64→x32) for seccomp bypass, shellcode with input reversal, .fini_array hijack, ret2vdso, pwntools template, x32 ABI syscall aliasing for seccomp bypass, time-based blind shellcode exfiltration
- [format-string.md](format-string.md) - Format string exploitation (leaks, GOT overwrite, blind pwn, filter bypass, canary leak, __free_hook, .rela.plt patching, saved EBP overwrite for .bss pivot, argv[0] overwrite for stack smash info leak, .fini_array loop for multi-stage exploitation, __printf_chk bypass with sequential %p, single-call leak + GOT overwrite, ROT13-encoded format string exploit through input transformation)
- [advanced.md](advanced.md) - Seccomp advanced techniques, UAF, JIT, esoteric GOT, heap overlap via base conversion, tree data structure stack underallocation, ret2dlresolve, kernel exploitation (basic)
- [heap-techniques.md](heap-techniques.md) - House of Apple 2 (+ setcontext SUID variant), House of Einherjar, House of Orange/Spirit/Lore/Force, heap grooming, custom allocators (nginx, talloc), classic unlink, musl libc heap (meta pointer + atexit hijack), tcache stashing unlink attack, unsafe unlink + top chunk consolidation
- [heap-techniques-2.md](heap-techniques-2.md) - CTF-writeup heap variants: UAF vtable pointer encoding shell argument, uninitialized chunk residue pointer leak, tcache strcpy null-byte overflow + backward consolidation, adjacent-struct fn-pointer overflow for libc leak + GOT overwrite, hidden-menu tcache poisoning, tcache double-free + fake _IO_FILE vtable stdout hijack, tcache-to-fastbin promotion cross-bin attack, 6-bit index OOB + written_bytes accumulator, IS_MMAPED bit-flip for unsorted bin leak on calloc'd chunk, filename-regex-constrained fastbin via LSB-only heap pointer overwrite, custom allocator unsafe unlink to GOT
- [heap-fsop.md](heap-fsop.md) - FILE-structure (_IO_FILE) exploitation: fastbin stdout vtable two-stage hijack for PIE + Full RELRO, _IO_buf_base null-byte stdin hijack, glibc 2.24+ _IO_FILE vtable validation bypass, unsorted-bin attack on stdin _IO_buf_end, unsorted-bin corruption via mp_ structure, realloc(ptr, 0) as free() UAF, single-byte reference counter wraparound UAF
- [advanced-exploits.md](advanced-exploits.md) - Advanced exploit techniques (part 1): VM signed comparison, BF JIT shellcode, type confusion, off-by-one index corruption, DNS overflow, ASAN shadow memory, format string with encoding constraints, custom canary preservation, signed integer bypass, canary-aware partial overflow, CSV injection, MD5 preimage gadgets, VM GC UAF slab reuse, path traversal sanitizer bypass, FSOP + seccomp bypass via openat/mmap/write
- [advanced-exploits-2.md](advanced-exploits-2.md) - Advanced exploit techniques (part 2): bytecode validator bypass via self-modification, io_uring UAF with SQE injection, integer truncation int32->int16, GC null-reference cascading corruption, leakless libc via multi-fgets stdout FILE overwrite, signed/unsigned char underflow heap overflow, XOR keystream brute-force write primitive, tcache pointer decryption heap leak, unsorted bin promotion via forged chunk size, FSOP stdout TLS leak, TLS destructor hijack via `__call_tls_dtors`, custom shadow stack pointer overflow bypass, signed int overflow negative OOB heap write, XSS-to-binary pwn bridge
- [advanced-exploits-4.md](advanced-exploits-4.md) - Advanced exploit techniques (part 4): Windows SEH overwrite + pushad VirtualAlloc ROP, IAT-relative resolution, detached process shell stability, SeDebugPrivilege SYSTEM escalation, ARM buffer overflow with Thumb shellcode, Forth interpreter system word exploitation, GF(2) Gaussian elimination for multi-pass tcache poisoning, single-bit-flip exploitation primitive (mprotect + iterative code patching), Game of Life shellcode evolution via still-lifes, UAF via menu-driven strdup/free ordering, Windows CFG bypass via system() as valid call target, neural network output as function pointer index OOB, shellcode unique-byte limit bypass via counter overflow
- [advanced-exploits-3.md](advanced-exploits-3.md) - Advanced exploit techniques (part 3): stack variable overlap / carry corruption OOB, 1-byte overflow via 8-bit loop counter, game AI arithmetic mean OOB read, arbitrary read/write GOT overwrite to shell, stack leak via __environ + memcpy overflow, JIT sandbox escape via uint16 jump truncation, DNS compression pointer stack overflow with multi-question ROP, ELF code signing bypass via program header manipulation, game level format signed/unsigned coordinate mismatch, file descriptor inheritance via missing O_CLOEXEC, sign extension integer underflow in metadata parsing, ROP chain construction with read-only primitive, 4-byte shellcode with timing side-channel via persistent registers, CRC oracle as arbitrary read, UTF-8 case conversion buffer overflow
- [advanced-exploits-5.md](advanced-exploits-5.md) - Advanced exploit techniques (part 5): data-interpretation exploitation — Chip-8 emulator OOB memory for ret2libc, double-precision float quicksort canary repositioning, bloom filter abs(INT_MIN) negative index OOB write
- [sandbox-escape.md](sandbox-escape.md) - Custom VM exploitation, FUSE/CUSE devices, busybox/restricted shell, shell tricks, process_vm_readv sandbox bypass, named pipe file size bypass, CPU emulator print opcode Python eval injection (cross-references ctf-misc/pyjails.md for Python jail techniques)
- [kernel.md](kernel.md) - Linux kernel exploitation fundamentals: environment setup, QEMU debug, heap spray structures (tty_struct, poll_list, user_key_payload, seq_operations), kernel stack overflow, canary leak, privilege escalation (ret2usr, kernel ROP), modprobe_path overwrite, core_pattern overwrite, kmalloc size mismatch heap overflow + struct file f_op corruption
- [kernel-techniques.md](kernel-techniques.md) - Kernel exploitation techniques: tty_struct kROP (fake vtable + stack pivot), AAW via ioctl register control, userfaultfd race stabilization, SLUB allocator internals (freelist hardening/obfuscation), leak via kernel panic, MADV_DONTNEED race window extension (DiceCTF 2026), cross-cache CPU-split attack (DiceCTF 2026), PTE overlap file write (DiceCTF 2026), addr_limit bypass via failed file open for kernel memory read/write
- [kernel-bypass.md](kernel-bypass.md) - Kernel protection bypass: KASLR/FGKASLR bypass (__ksymtab), KPTI bypass (swapgs trampoline, signal handler, modprobe_path/core_pattern via ROP), SMEP/SMAP bypass, GDB kernel module debugging, initramfs/virtio-9p workflow, exploit templates, exploit delivery
- [field-notes.md](field-notes.md) - Detailed pwn notes: heap exploitation quick reference, additional exploit notes, useful commands
- [attack-playbook.md](attack-playbook.md) - Linux userland attack playbook: recon of input/privilege boundaries, leak selection by mitigation, and primitive ranking workflow
- [static-signals.md](static-signals.md) - Exploit-relevant static signals (libc version, seccomp policy, RELRO/PIE/canary/NX evidence) for exploitability assessment
- [pwnable-tw/README.md](pwnable-tw/README.md) - 43 pwnable.tw writeups (orw, start, calc, hacknote, babystack, tcache_tear, death_note, dubblesort, applestore, bookwriter, and more) with per-challenge environment, protections, root-cause defects, and concrete exploitation chains
- [tools-mcp.md](tools-mcp.md) - MCP server integration for pwn: WinDbg MCP session model (`open_cdb_dump`/`open_cdb_remote`/`open_kd_session` + `session_id`), crash-dump triage, in-dump flag-prefix memory scanning, live breakpoint/hardware-watchpoint/memory-patch exploitation, `!dh -f` Windows mitigation check (the `checksec` equivalent), kernel-mode token stealing with kd; IDA/Ghidra MCP for exploit development (decompile the vulnerable function first, drop to assembly only for exact gadget bytes)

---

## ROP Chain Building

Leak libc via `puts@PLT(puts@GOT)`, return to vuln, stage 2 with `system("/bin/sh")`. See [rop-and-shellcode.md](rop-and-shellcode.md) for full two-stage ret2libc pattern, leak parsing, and return target selection.

**DynELF libc discovery:** `pwntools.DynELF(leak_func, pointer_in_libc)` resolves libc symbols remotely without knowing the libc version. See [rop-and-shellcode.md](rop-and-shellcode.md#dynelf-automated-libc-discovery-rc3-ctf-2016).

**Constrained shellcode in small buffers:** When buffer is too small, use `read()` shellcode stub (< 20 bytes) to pull full stage-2 shellcode. See [rop-and-shellcode.md](rop-and-shellcode.md#constrained-shellcode-in-small-buffers-tum-ctf-2016).

**Raw syscall ROP:** When `system()`/`execve()` crash (CET/IBT), use `pop rax; ret` + `syscall; ret` from libc. See [rop-and-shellcode.md](rop-and-shellcode.md).

**ret2csu:** `__libc_csu_init` gadgets control `rdx`, `rsi`, `edi` and call any GOT function — universal 3-argument call without libc gadgets. See [rop-and-shellcode.md](rop-and-shellcode.md#ret2csu--__libc_csu_init-gadgets-crypto-cat).

**Bad char XOR bypass:** XOR payload data with key before writing to `.data`, then XOR back in place with ROP gadgets. Avoids null bytes, newlines, and other filtered characters. See [rop-and-shellcode.md](rop-and-shellcode.md#bad-character-bypass-via-xor-encoding-in-rop-crypto-cat).

**Exotic gadgets (BEXTR/XLAT/STOSB/PEXT):** When standard `mov` write gadgets are unavailable, chain obscure x86 instructions for byte-by-byte memory writes. See [rop-and-shellcode.md](rop-and-shellcode.md#exotic-x86-gadgets--bextrxlatstosbpext-crypto-cat).

**Stack pivot (xchg rax,esp):** Swap stack pointer to attacker-controlled heap/buffer when overflow is too small for full ROP chain. Requires `pop rax; ret` to load pivot address first. See [rop-and-shellcode.md](rop-and-shellcode.md#stack-pivot-via-xchg-raxesp-crypto-cat).

**rdx control:** After `puts()`, rdx is clobbered to 1. Use `pop rdx; pop rbx; ret` from libc, or re-enter binary's read setup + stack pivot. See [rop-and-shellcode.md](rop-and-shellcode.md).

**Canary XOR epilogue as rdx zeroing gadget:** When no `pop rdx; ret` exists, jump into the canary check epilogue `xor rdx, fs:28h` -- it zeros RDX when the canary is intact. See [rop-and-shellcode.md](rop-and-shellcode.md#stack-canary-xor-epilogue-as-rdx-zeroing-gadget-volgactf-2017).

**stub_execveat as execve alternative:** When no `pop rax; ret` exists, use `stub_execveat` (syscall 322/0x142) instead of `execve` -- send exactly 0x142 bytes so `read()` return value sets rax. See [rop-and-shellcode.md](rop-and-shellcode.md#stub_execveat-syscall-as-execve-alternative-asis-ctf-2018).

**Shell interaction:** After `execve`, `sleep(1)` then `sendline(b'cat /flag*')`. See [rop-and-shellcode.md](rop-and-shellcode.md).

## Kernel Exploitation

**addr_limit bypass via failed file open:** When a kernel module sets `addr_limit = KERNEL_DS` but fails to restore it on error paths, force the error (e.g., make target file a directory) to retain kernel memory access from userspace `read()`/`write()`. See [kernel-techniques.md](kernel-techniques.md#kernel-addr_limit-bypass-via-failed-file-open-midnight-sun-ctf-2018).

## Advanced Exploit Primitives

**Neural network function pointer OOB:** When a binary uses NN output as an index into a function pointer array without bounds checking, retrain weights/biases to produce an out-of-bounds index that reads a target address from the biases array. See [advanced-exploits-4.md](advanced-exploits-4.md#neural-network-output-as-function-pointer-index-oob-swampctf-2018).

**Shellcode unique-byte limit bypass via counter overflow:** When shellcode is limited to N unique bytes, spray the stack to corrupt the `seen[256]` counter, then re-execute main (skipping `memset`) so the overflowed counter allows arbitrary bytes on the second run. See [advanced-exploits-4.md](advanced-exploits-4.md#shellcode-unique-byte-limit-bypass-via-counter-overflow-blaze-ctf-2018).

## Deep-Dive Notes

Use [field-notes.md](field-notes.md) once you have confirmed the challenge is truly exploitation-heavy.

- Heap and allocator notes: House of Apple, tcache, unsafe unlink, talloc, UAF, FSOP
- Advanced exploit notes: seccomp bypass, ret2vdso, io_uring, integer truncation, ASAN, timing oracles
- Sandbox and hybrid notes: pyjail crossover, busybox escapes, custom VMs, shell tricks, path sanitizers
- Kernel and Windows notes: kernel playbooks, SEH, CFG bypass, privilege escalation
- Historical case notes: older but still reusable CTF exploit patterns
