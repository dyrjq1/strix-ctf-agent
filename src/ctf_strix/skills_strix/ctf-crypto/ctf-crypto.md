---
name: ctf-crypto
description: Provides cryptography attack techniques for CTF challenges. Use when attacking encryption, hashing, signatures, ZKP, PRNG, or mathematical crypto problems involving RSA, AES, ECC, lattices, LWE, CVP, number theory, Coppersmith, Pollard, Wiener, padding oracle, GCM, key derivation, or stream/block cipher weaknesses.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash and Python 3.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF Cryptography

Quick reference for crypto CTF challenges. Each technique has a one-liner here; see supporting files for full details with code.

## Prerequisites

**Python packages:** the image already ships `pycryptodome`,
`pycryptodomex`, `z3-solver`, `sympy`, and `gmpy2`. `hashpumpy`, `fpylll`,
`py_ecc`, and the `coppersmith` / `crypto-attacks` helpers are **not
available** (nothing can be installed here) -- implement those steps with `sympy`/`z3`
or pure Python instead.

**Offline image: no installs and no internet.** `python3` ships `gmpy2`,
`sympy` and `z3-solver` (so no libgmp build step is needed); `RsaCtfTool` is
installed (offline, no factordb by default); `hashcat` and SageMath are not
available -- [advanced-math.md](advanced-math.md) Coppersmith pseudocode (its
LLL step needs fpylll, not in the image: hand-write LLL in python3) and
pure-Python attacks.

## Additional Resources

- [classic-ciphers.md](classic-ciphers.md) - Classic ciphers: Vigenere (+ Kasiski examination), Atbash, substitution wheels, XOR variants (+ multi-byte frequency analysis), deterministic OTP, cascade XOR, book cipher, OTP key reuse / many-time pad, variable-length homophonic substitution, grid permutation cipher keyspace reduction, image-based Caesar shift ciphers, XOR key recovery via file format headers
- [modern-ciphers.md](modern-ciphers.md) - Modern cipher attacks: AES (CFB-8, ECB leakage), CBC-MAC/OFB-MAC, padding oracle, S-box collisions, GF(2) elimination, LCG partial output recovery, affine cipher over composite modulus, AES-GCM with derived keys, AES-GCM nonce reuse (forbidden attack), Ascon-like reduced-round differential cryptanalysis, custom linear MAC forgery, CBC padding oracle (full block decryption), Bleichenbacher RSA PKCS#1 v1.5 padding oracle (ROBOT), birthday attack / meet-in-the-middle, CRC32 collision signature forgery, AES key recovery via byte-by-byte zeroing oracle, AES-CBC ciphertext forging via error-message decryption oracle
- [modern-ciphers-2.md](modern-ciphers-2.md) - Modern cipher attacks (Part 2): Blum-Goldwasser bit-extension oracle, hash length extension, compression oracle (CRIME-style), hash function time reversal via cycle detection, OFB mode invertible RNG backward decryption, weak key derivation via public key hash XOR, HMAC-CRC linearity attack, DES weak keys in OFB mode, SRP protocol bypass, modified AES S-Box brute-force, square attack on reduced-round AES, AES-ECB byte-at-a-time chosen plaintext, AES-ECB cut-and-paste block manipulation, AES-CBC IV bit-flip auth bypass, Rabin LSB parity oracle, PBKDF2 pre-hash bypass, MD5 multi-collision via fastcol
- [modern-ciphers-3.md](modern-ciphers-3.md) - Modern cipher attacks (Part 3): custom hash state reversal, CRC32 brute-force for small payloads, noisy RSA LSB oracle error correction, sponge hash MITM collision, CBC IV forgery + block truncation, padding oracle to CBC bitflip RCE, SPN S-box intersection attack, AES-CFB IV recovery from timestamp-seeded PRNG, three-round XOR protocol key cancellation, AES-CBC UnicodeDecodeError side-channel oracle, SHA-256 basis attack for XOR-aggregate hash bypass, custom MAC forgery via XOR block cancellation, HMAC key recovery via XOR+addition arithmetic
- [modern-ciphers-4.md](modern-ciphers-4.md) - Modern cipher attacks (Part 4): ChaCha20-Poly1305 nonce reuse forbidden attack over $2^{130}-5$ (RFC 8439, CTR $C_1\oplus C_2=P_1\oplus P_2$, Poly1305 $\sum c_i r^{n-i}$ via galois/sympy, 2-msg $ad=""$ vectors), partitioning-oracle / key-committing AEAD splitting lattice, sponge generality (SHA-3/Keccak $0x06$ vs $0x01$, Ascon/Gimli/Sparkle rate/capacity/rounds/pad table + endianness workflow), eSTREAM Trivium 1152-round warmup & cube attack outline (Grain)
- [stream-ciphers.md](stream-ciphers.md) - Stream cipher attacks: LFSR (Berlekamp-Massey, correlation attack, known-plaintext, Galois vs Fibonacci, Galois tap recovery via autocorrelation), RC4 second-byte bias, XOR consecutive byte correlation
- [rsa-attacks.md](rsa-attacks.md) - RSA attacks: small e (cube root), common modulus, Wiener's, Pollard's p-1, Hastad's broadcast, Hastad with linear padding (Coppersmith), Franklin-Reiter related message (e=3), Coppersmith linearly-related primes, Fermat/consecutive primes, multi-prime, restricted-digit, Coppersmith structured primes, Manger oracle, polynomial hash
- [rsa-attacks-2.md](rsa-attacks-2.md) - RSA attacks (specialized): RSA p=q validation bypass, cube root CRT gcd(e,phi)>1, factoring from phi(n) multiple, multiplicative homomorphism signature forgery, weak keygen via base representation, RSA with gcd(e,phi)>1 exponent reduction, batch GCD shared prime factoring, partial key recovery from dp/dq/qinv, RSA-CRT fault attack, homomorphic decryption oracle bypass, small prime CRT decomposition, Montgomery reduction timing attack, Bleichenbacher low-exponent signature forgery, RSA signature bypass with e=1 and crafted modulus
- [ecc-attacks.md](ecc-attacks.md) - ECC attacks: small subgroup, invalid curve, Smart's attack (anomalous, with Sage code), fault injection, clock group DLP, Pohlig-Hellman, ECDSA nonce reuse, Ed25519 torsion side channel, DSA nonce reuse, DSA key recovery via MD5 collision on k-generation, X25519 low-order points + all-zero check
- [dh-attacks.md](dh-attacks.md) - Classic finite-field DH: trivial g (0/1/p-1), Pohlig-Hellman when p-1 smooth, small-subgroup confinement / Lim-Lee static key recovery via CRT, static vs ephemeral + Logjam downgrade triage
- [zkp-and-advanced.md](zkp-and-advanced.md) - ZKP/graph 3-coloring, Z3 solver guide, garbled circuits, Shamir SSS, bigram constraint solving, race conditions, Groth16 broken setup, DV-SNARG forgery, KZG pairing oracle for permutation recovery, Shamir SSS reused polynomial coefficients
- [prng.md](prng.md) - PRNG attacks (foundational): MT19937, MT float recovery via GF(2) magic matrix for token prediction, LCG, GF(2) matrix PRNG, V8 XorShift128+ Math.random state recovery via Z3, middle-square, deterministic RNG hill climbing, random-mode oracle, time-based seeds, C srand/rand synchronization via ctypes, password cracking, logistic map chaotic PRNG
- [prng-attacks.md](prng-attacks.md) - PRNG attacks (CTF-era, 2017+): MT subset-sum seed recovery, MT19937 constraint propagation, Rule 86 cellular automaton reversal via Z3, Java LCG meet-in-the-middle partial modulo, LCG backward stepping via modular inverse, LFSR bit-fold ASCII parity, Z3 solve-time timing oracle, randcrack DSA k prediction, format-string PRNG seed offset, NTP-poisoned PRNG UUID XOR
- [historical.md](historical.md) - Historical ciphers (Lorenz SZ40/42, book cipher implementation)
- [advanced-math.md](advanced-math.md) - Advanced mathematical attacks (isogenies, Pohlig-Hellman, baby-step giant-step (BSGS) for general DLP, LLL, Merkle-Hellman knapsack via LLL, Coppersmith via Howgrave-Graham hg_matrix -> IntegerMatrix -> LLL -> sympy Poly (beta=0.5, monic check, flatter optional dim>100), quaternion RSA, GF(2)[x] CRT, S-box collision code, LWE lattice CVP attack, affine cipher over non-prime modulus, introspective CRC via GF(2) linear algebra)
- [lattice-and-lwe.md](lattice-and-lwe.md) - Lattice attack triage and workflow: LLL/BKZ/Babai, HNP from partial or biased nonces, truncated LCG state recovery, LWE embedding and CVP, Ring-LWE / Module-LWE recognition, NTRU lattice B=[[qI 0],[H I]] (negacyclic, BKZ, centered g), GGH embedding [[B 0],[c lambda]] sweep lambda, Mersenne AJPS p=2^n-1 n=11213 w=10 6x6 s=5, BDD predicate/LadderLeak >100 sigs 1-4 bits, orthogonal lattices, subset sum / knapsack, and common failure modes
- [post-quantum.md](post-quantum.md) - Post-quantum recognition: ML-KEM (Kyber) k=2/3/4 q=3329 etau dv, ML-DSA, Falcon, Module-LWE flattening, FO failure oracle, NTT, Kannan/Bai-Galbraith/Arora-Ge/estimator decision tree, Mersenne AJPS details
- [exotic-crypto.md](exotic-crypto.md) - Exotic algebraic structures (braid group DH / Alexander polynomial, monotone function inversion, tropical semiring residuation, Paillier cryptosystem, Hamming code helical interleaving, ElGamal universal re-encryption, FPE Feistel brute-force, icosahedral symmetry group cipher, Goldwasser-Micali replication oracle)
- [exotic-crypto-2.md](exotic-crypto-2.md) - Exotic algebraic structures (Part 2, 2017+): BB-84 QKD MITM, ElGamal trivial DLP (B=p-1), Paillier LSB oracle via homomorphic doubling, differential privacy noise cancellation, homomorphic encryption bit-extraction, ElGamal over matrices via Jordan normal form, OSS signature forgery via Pollard, Cayley-Purser decryption without private key, BIP39 partial mnemonic checksum brute force, Asmuth-Bloom CRT threshold recovery, Rabin with polynomial primes, LCG period detection, Vandermonde polynomial coefficient recovery

---

## When to Pivot

- If the real blocker is understanding a binary, obfuscated client, or weird VM, switch to `/ctf-reverse`.
- If the challenge is mostly packet carving, disk recovery, or stego extraction before any decryption starts, switch to `/ctf-forensics`.
- If the task is just implementing an exploit against a vulnerable network service after the crypto part is solved, switch to `/ctf-pwn` or `/ctf-web`.
- If the crypto challenge involves adversarial ML, model extraction, or neural-network-based ciphers, switch to `/ctf-ai-ml`.
- If the challenge is really an encoding puzzle, esoteric cipher, or polyglot trick rather than true cryptanalysis, switch to `/ctf-misc`.

## Quick Start Commands

```bash
# Identify cipher type
python3 -c "from Crypto.Util.number import *; n=<N>; print(f'bits={n.bit_length()}')"

# RSA quick check
python3 -c "from sympy import factorint; print(factorint(<n>))"  # Small factors?
python3 -c "from Crypto.PublicKey import RSA; k = RSA.import_key(open('key.pub').read()); print(k.n, k.e)"  # n, e from PEM via pycryptodome (openssl CLI is not in the image)

# Quick factorization tools (RsaCtfTool is installed; sympy also works)
python3 -c "from sympy import factorint; print(factorint(<n>))"  # then invert e mod lambda(n)

# XOR analysis
python3 -c "from pwn import xor; print(xor(bytes.fromhex('<hex>'), b'flag{'))"

# Hash identification (no hashid/hashcat): 32 hex = MD5, 40 hex = SHA-1,
# 64 hex = SHA-256; anything salted or iterated -> read the challenge code

# Quick factorization (sympy, primary)
python3 -c "from sympy import factorint; print(factorint(<n>))"
# No SageMath in the image: the sympy factorint line above is the factoring path (RsaCtfTool for bigger composites)
```

## Classic Ciphers

- **Caesar:** Frequency analysis or brute force 26 keys
- **Vigenere:** Known plaintext attack with flag format prefix; derive key from `(ct - pt) mod 26`. Kasiski examination for unknown key length (GCD of repeated sequence distances)
- **Atbash:** A<->Z substitution; look for "Abashed" hints in challenge name
- **Substitution wheel:** Brute force all rotations of inner/outer alphabet mapping
- **Multi-byte XOR:** Split ciphertext by key position, frequency-analyze each column independently; score by English letter frequency (space = 0x20)
- **Cascade XOR:** Brute force first byte (256 attempts), rest follows deterministically
- **XOR rotation (power-of-2):** Even/odd bits never mix; only 4 candidate states
- **Weak XOR verification:** Single-byte XOR check has 1/256 pass rate; brute force with enough budget
- **Deterministic OTP:** Known-plaintext XOR to recover keystream; match load-balanced backends
- **OTP key reuse (many-time pad):** `C1 XOR C2 XOR known_P = unknown_P`; crib dragging when no plaintext known
- **Homophonic (variable-length):** Multi-character ciphertext groups map to single plaintext chars. Find n-grams with identical sub-n-gram frequencies, replace with symbols, solve as monoalphabetic. See [classic-ciphers.md](classic-ciphers.md#variable-length-homophonic-substitution-asis-ctf-finals-2013).
- **Grid permutation cipher:** 5x5 grid with independent row/column permutations collapses keyspace to 5! x 5! = 14,400; brute-force in milliseconds. See [classic-ciphers.md](classic-ciphers.md#grid-permutation-cipher-keyspace-reduction-bsidessf-2026).
- **Image-based Caesar shift:** Pixel rows/columns shifted by per-strip offsets; compare original vs shifted image to extract ASCII-encoded flag from shift amounts. See [classic-ciphers.md](classic-ciphers.md#image-based-caesar-shift-ciphers-bsidessf-2026).
- **Polybius square cipher:** 5x5 grid maps letter pairs to plaintext; digits/coordinates encode positions. See [classic-ciphers.md](classic-ciphers.md#polybius-square-cipher-qiwi-infosec-2016).
- **XOR key recovery via file format headers:** File claims to be PDF/PNG/ZIP but `file` reports "data". XOR first bytes against expected magic bytes to derive repeating key; extend using trailer structures (`%%EOF`, IEND marker). See [classic-ciphers.md](classic-ciphers.md#xor-key-recovery-via-file-format-headers-metactf-flash-2026).

See [classic-ciphers.md](classic-ciphers.md) for full code examples.

## Modern Cipher Attacks

- **AES-ECB:** Block shuffling, byte-at-a-time chosen-plaintext suffix recovery (256 queries per byte, tool: FeatherDuster `ecb_cpa_decrypt`); image ECB preserves visual patterns. ECB cut-and-paste: splice ciphertext blocks to forge JSON fields (e.g., `is_admin: true`). See [modern-ciphers-2.md](modern-ciphers-2.md#aes-ecb-byte-at-a-time-chosen-plaintext-abctf-2016).
- **AES-CBC:** Bit flipping to change plaintext; padding oracle for decryption without key. IV bit-flip: flip specific bits in the IV to change first plaintext block (requires no MAC). See [modern-ciphers-2.md](modern-ciphers-2.md#aes-cbc-iv-bit-flip-authentication-bypass-google-ctf-2016).
- **CBC IV forgery + block truncation:** XOR IV bytes to change decrypted block 0; strip trailing ciphertext blocks (no length integrity in CBC). Forges authenticated tokens when MAC is embedded in the ciphertext. See [modern-ciphers-3.md](modern-ciphers-3.md#cbc-iv-forgery--block-truncation-for-authentication-bypass-0ctf-2017).
- **Padding oracle to CBC bitflip RCE:** Chain padding oracle (recover plaintext) with CBC bitflipping (inject shell metacharacters) for command injection via encrypted parameters. See [modern-ciphers-3.md](modern-ciphers-3.md#padding-oracle-to-cbc-bitflip-command-injection-bsidessf-2017).
- **AES-CFB-8:** Static IV with 8-bit feedback allows state reconstruction after 16 known bytes
- **CBC-MAC/OFB-MAC:** XOR keystream for signature forgery: `new_sig = old_sig XOR block_diff`
- **S-box collisions:** Non-permutation S-box (`len(set(sbox)) < 256`) enables 4,097-query key recovery
- **GF(2) elimination:** Linear hash functions (XOR + rotations) solved via Gaussian elimination over GF(2)
- **Padding oracle:** Byte-by-byte decryption by modifying previous block and testing padding validity
- **LFSR stream ciphers:** Berlekamp-Massey recovers feedback polynomial from 2L keystream bits; correlation attack breaks combined generators with biased combining functions
- **Galois LFSR tap recovery:** XOR known file header (PNG/PDF/ZIP) with ciphertext to get keystream; split into N-bit windows, compute `(state >> 1) XOR next_state` for LSB=1 transitions to directly recover tap mask. Autocorrelation sliding finds correct length. See [stream-ciphers.md](stream-ciphers.md#galois-lfsr-tap-recovery-via-autocorrelation-bsidessf-2026).
- **OFB with invertible RNG:** Known plaintext in any block leaks RNG state; if state transition is bijective, run RNG backwards to decrypt all blocks. See [modern-ciphers-2.md](modern-ciphers-2.md#ofb-mode-with-invertible-rng-backward-decryption-bsidessf-2026).
- **Weak key derivation (public key hash XOR):** AES key derived from `SHA256(public_key) XOR seed` is fully recoverable without private key; "hybrid" RSA+AES provides no security. See [modern-ciphers-2.md](modern-ciphers-2.md#weak-key-derivation-via-public-key-hash-xor-bsidessf-2026).
- **HMAC-CRC linearity:** CRC is linear over GF(2), so HMAC-CRC key is recoverable from a single message-MAC pair via polynomial arithmetic. See [modern-ciphers-2.md](modern-ciphers-2.md#hmac-crc-linearity-attack-boston-key-party-2016).
- **DES weak keys in OFB:** 4 DES weak keys make encryption self-inverse; OFB keystream cycles with period 2, reducing to 16-byte repeating XOR. See [modern-ciphers-2.md](modern-ciphers-2.md#des-weak-keys-in-ofb-mode-boston-key-party-2016).
- **Square attack (reduced-round AES):** 4-round AES broken by integral cryptanalysis: 256-plaintext lambda set, guess last round key bytes via XOR-sum = 0 distinguisher. See [modern-ciphers-2.md](modern-ciphers-2.md#square-attack-on-reduced-round-aes-0ctf-2016).
- **AES-GCM nonce reuse (forbidden attack):** Same nonce = CTR keystream reuse + GHASH authentication key recovery via polynomial factoring over GF(2^128). Tool: `nonce-disrespect`. See [modern-ciphers.md](modern-ciphers.md#aes-gcm-nonce-reuse--forbidden-attack).
- **SRP protocol bypass:** Send `A = 0` or `A = n` to force shared secret to 0, bypassing password verification entirely. See [modern-ciphers-2.md](modern-ciphers-2.md#srp-secure-remote-password-protocol-bypass-via-modular-arithmetic-asis-ctf-finals-2016).
- **Modified AES S-Box brute force:** Custom S-Box with only 16 unique outputs reduces key entropy; brute-force feasible key bytes per round. See [modern-ciphers-2.md](modern-ciphers-2.md#modified-aes-s-box-brute-force-recovery-h4ckit-ctf-2016).
- **Rabin LSB parity oracle:** Rabin ciphertext `c = m^2 mod n` with LSB oracle enables binary search plaintext recovery in `log2(n)` queries via multiplicative homomorphism (`c * 4 mod n` doubles plaintext). See [modern-ciphers-2.md](modern-ciphers-2.md#rabin-cryptosystem-lsb-parity-oracle-plaidctf-2016).
- **Noisy RSA LSB oracle error correction:** When LSB oracle has sporadic errors, run standard attack then inspect output charset. Flip oracle results at error positions to correct remaining decryption. See [modern-ciphers-3.md](modern-ciphers-3.md#noisy-rsa-lsb-oracle-with-post-hoc-error-correction-sharifctf-7-2016).
- **PBKDF2 pre-hash bypass:** HMAC pre-hashes keys > 64 bytes (SHA-1/SHA-256 block size). Login with `SHA1(password)` instead of `password` when original exceeds 64 bytes. See [modern-ciphers-2.md](modern-ciphers-2.md#pbkdf2-pre-hash-bypass-for-long-passwords-backdoorctf-2016).
- **MD5 multi-collision (fastcol):** Chain `fastcol` runs to produce 2^k files with identical MD5. Merkle-Damgard composition: collisions propagate through appended suffixes. See [modern-ciphers-2.md](modern-ciphers-2.md#md5-multi-collision-via-fastcol-backdoorctf-2016).
- **Custom hash state reversal:** When iterative hash leaks intermediate states, isolate per-block hash values by inverting the state update equation, then brute-force each 4-byte block independently. See [modern-ciphers-3.md](modern-ciphers-3.md#custom-hash-state-reversal-via-known-intermediates-backdoorctf-2016).
- **CRC32 brute-force (small payloads):** ZIP CRC32 headers are unencrypted; brute-force content of small files (≤ 6 bytes) by checking all printable strings against stored CRC32. See [modern-ciphers-3.md](modern-ciphers-3.md#crc32-brute-force-for-small-payloads-backdoorctf-2016).
- **Custom MAC forgery via XOR block cancellation:** When MAC key stream repeats periodically, craft three queries where filler blocks cancel via XOR, forging any target command's MAC. See [modern-ciphers-3.md](modern-ciphers-3.md#custom-mac-forgery-via-xor-block-cancellation-with-key-rotation-plaidctf-2018).
- **HMAC key recovery (XOR + addition arithmetic):** Flawed HMAC using `sha256((key XOR msg) + msg)` leaks key bits: `msg=0` gives `sha256(key)`, `msg=2^i` matches iff key bit `i` is set. See [modern-ciphers-3.md](modern-ciphers-3.md#bit-by-bit-hmac-key-recovery-via-xor-plus-addition-arithmetic-midnight-sun-ctf-2018).
- **AES-CBC ciphertext forging (error-message oracle):** Server leaks decrypted bytes in error messages; send zero blocks to learn intermediate state, XOR with desired plaintext to forge ciphertext block-by-block. See [modern-ciphers.md](modern-ciphers.md#aes-cbc-ciphertext-forging-via-error-message-decryption-oracle-nuit-du-hack-ctf-2018).

See [modern-ciphers.md](modern-ciphers.md) and [modern-ciphers-2.md](modern-ciphers-2.md) for full code examples.

## RSA Attacks

- **Small e with small message:** Take eth root
- **Common modulus:** Extended GCD attack
- **Wiener's attack:** Small d
- **Fermat factorization:** p and q close together
- **Pollard's p-1:** Smooth p-1
- **Hastad's broadcast:** Same message, multiple e=3 encryptions
- **Consecutive primes:** q = next_prime(p); find first prime below sqrt(N)
- **Multi-prime:** Factor N with sympy; compute phi from all factors
- **Restricted-digit primes:** Digit-by-digit factoring from LSB with modular pruning
- **Coppersmith structured primes:** Partially known prime; small_roots via coppersmith lib (Sage fallback in details)
- **Manger oracle (simplified):** Phase 1 doubling + phase 2 binary search; ~128 queries for 64-bit key
- **Manger on RSA-OAEP (timing):** Python `or` short-circuit skips expensive PBKDF2 when Y != 0, creating fast/slow timing oracle. Full 3-step attack (~1024 iterations for 1024-bit RSA). Calibrate timing bounds with known-fast/known-slow samples.
- **Polynomial hash (trivial root):** `g(0) = 0` for polynomial hash; craft suffix for `msg = 0 (mod P)`, signature = 0
- **Polynomial CRT in GF(2)[x]:** Collect ~20 remainders `r = flag mod f`, filter coprime, CRT combine
- **Affine over composite modulus:** CRT in each prime factor field; Gauss-Jordan per prime
- **RSA p=q validation bypass:** Set `p=q` so server computes wrong `phi=(p-1)^2` instead of `p*(p-1)`; test decryption fails, leaking ciphertext
- **RSA cube root CRT (gcd(e,phi)>1):** When all primes ≡ 1 mod e, compute eth roots per-prime via `nthroot_mod`, enumerate CRT combinations (3^k feasible for small k)
- **Factoring from phi(n) multiple:** Any multiple of `phi(n)` (e.g., `e*d-1`) enables factoring via Miller-Rabin square root technique; succeeds with prob ≥ 1/2 per attempt
- **Weak keygen via base representation:** Primes `p = kp*B + tp` with small kp create mixed-radix structure in n; brute-force kp*kq (2^24) to factor
- **RSA with gcd(e,phi)>1 (exponent reduction):** Reduce `e' = e/g`, compute `d' = e'^(-1) mod phi`, partial decrypt to `m^g`, then take g-th root over integers
- **RSA partial key recovery (dp/dq/qinv):** CRT exponents from partial PEM leak allow O(e) prime recovery: iterate k, check if `(dp*e-1)/k+1` is prime. See [rsa-attacks-2.md](rsa-attacks-2.md#rsa-partial-key-recovery-from-dp-dq-qinv-0ctf-2016).
- **RSA-CRT fault attack:** Single faulty CRT signature leaks factor via `gcd(s^e - m, n)` (Bellcore attack). See [rsa-attacks-2.md](rsa-attacks-2.md#rsa-crt-fault-attack--bit-flip-recovery-csaw-ctf-2016).
- **RSA homomorphic decryption bypass:** Multiplicative homomorphism lets you decrypt `c` by querying oracle with `c * r^e mod n`, then dividing result by `r`. See [rsa-attacks-2.md](rsa-attacks-2.md#rsa-homomorphic-decryption-oracle-bypass-ectf-2016).
- **RSA small prime CRT decomposition:** When `n` has many small prime factors, factor with trial division, solve `m mod p_i` per prime, CRT combine. See [rsa-attacks-2.md](rsa-attacks-2.md#rsa-with-small-prime-factors-and-crt-decomposition-hack-the-vote-2016).
- **Hastad broadcast with linear padding (Coppersmith):** When each of `e` recipients applies a known affine transform `a_i*m+b_i` before encryption, CRT + Coppersmith small_roots recovers `m`. See [rsa-attacks.md](rsa-attacks.md#hastad-broadcast-attack-with-linear-padding----coppersmith-plaidctf-2017).
- **RSA Montgomery reduction timing attack:** Leaked extra-subtraction counts in Montgomery multiplication reveal private key bits MSB-to-LSB via statistical correlation. See [rsa-attacks-2.md](rsa-attacks-2.md#rsa-timing-attack-on-montgomery-reduction-def-con-2017).
- **Bleichenbacher low-exponent signature forgery:** With e=3, forge PKCS#1 v1.5 signatures by computing cube root of a value with correct padding prefix; trailing garbage absorbs the remainder. See [rsa-attacks-2.md](rsa-attacks-2.md#bleichenbacher-low-exponent-rsa-signature-forgery-google-ctf-2017).
- **Franklin-Reiter related message attack (e=3):** Two ciphertexts of `m+pad1` and `m+pad2` with known padding difference; polynomial GCD in `Zmod(n)` recovers `m` directly. See [rsa-attacks.md](rsa-attacks.md#franklin-reiter-related-message-attack-on-rsa-e3-n1ctf-2018).
- **RSA signature bypass (e=1, crafted modulus):** Verifier accepts user-supplied `(n, e)`; set `e=1` and `n = sig - PKCS1_pad(msg)` so `pow(sig, 1, n)` equals expected padded hash. See [rsa-attacks-2.md](rsa-attacks-2.md#rsa-signature-bypass-with-e1-and-crafted-modulus-backdoorctf-2018).
- **Coppersmith on linearly-related primes:** When `q ~ k*p` for known `k`, approximate `q ~ sqrt(k*n)` and use Coppersmith `small_roots` on the error term. Generalizes Fermat factorization to non-consecutive primes. See [rsa-attacks.md](rsa-attacks.md#coppersmith-attack-on-linearly-related-rsa-primes-asis-ctf-2018).

See [rsa-attacks.md](rsa-attacks.md) and [advanced-math.md](advanced-math.md) for full code examples.

## Elliptic Curve Attacks

- **Small subgroup:** Check curve order for small factors; Pohlig-Hellman + CRT
- **Invalid curve:** Send points on weaker curves if validation missing
- **Singular curves:** Discriminant = 0; DLP maps to additive/multiplicative group
- **Smart's attack:** Anomalous curves (order = p); p-adic lift solves DLP in O(1)
- **Baby-step giant-step (BSGS):** General DLP in O(sqrt(n)) time/space. Combined with Pohlig-Hellman for smooth-order groups (all factors of `p-1` or curve order are small). sympy/fpylll BSGS+Pohlig-Hellman (Sage alternative collapsed). See [advanced-math.md](advanced-math.md#baby-step-giant-step-for-general-dlp).
- **Fault injection:** Compare correct vs faulty output; recover key bit-by-bit
- **Clock group (x^2+y^2=1):** Order = p+1 (not p-1!); Pohlig-Hellman when p+1 is smooth
- **Isogenies:** Graph traversal via modular polynomials; pathfinding via LCA
- **ECDSA nonce reuse:** Same `r` in two signatures leaks nonce `k` and private key `d` via modular arithmetic. Check for repeated `r` values
- **Braid group DH:** Alexander polynomial is multiplicative under braid concatenation — Eve computes shared secret from public keys. See [exotic-crypto.md](exotic-crypto.md#braid-group-dh--alexander-polynomial-multiplicativity-dicectf-2026)
- **Ed25519 torsion side channel:** Cofactor h=8 leaks secret scalar bits when key derivation uses `key = master * uid mod l`; query powers of 2, check y-coordinate consistency
- **Tropical semiring residuation:** Tropical (min-plus) DH is broken — residual `b* = max(Mb[i] - M[i][j])` recovers shared secret directly from public matrices
- **FPE Feistel brute-force:** Format-preserving encryption with 16-bit round key is brute-forceable; remaining affine GF(2) mixing layer solved via Gaussian elimination. See [exotic-crypto.md](exotic-crypto.md#format-preserving-encryption-feistel-brute-force-bsidessf-2026)
- **Icosahedral symmetry cipher:** Dodecahedron face permutations form order-120 group; build lookup table of all permutations via API probing, match visible face patterns. See [exotic-crypto.md](exotic-crypto.md#icosahedral-symmetry-group-cipher-bsidessf-2026)
- **Goldwasser-Micali replication oracle:** GM encrypts one bit per ciphertext; replaying a single ciphertext value N times as an N-bit key forces all-zero or all-one key, distinguishable via hash oracle. 128 queries recover full AES key. See [exotic-crypto.md](exotic-crypto.md#goldwasser-micali-ciphertext-replication-oracle-bsidessf-2026)
- **DSA nonce reuse:** Same r in two DSA signatures leaks private key via same formula as ECDSA nonce reuse. See [ecc-attacks.md](ecc-attacks.md#dsa-nonce-reuse-for-private-key-recovery-volgactf-2016).
- **DSA limited k brute force:** When nonce `k` is small (e.g., 20-bit), brute-force all `k` values and check which yields the known `r`. See [ecc-attacks.md](ecc-attacks.md#dsa-limited-k-value-brute-force-asis-ctf-finals-2016).
- **ECC shared prime GCD:** Multiple ECC curves sharing a prime factor in their modulus; `gcd(n1, n2)` reveals the shared prime. See [ecc-attacks.md](ecc-attacks.md#ecc-shared-prime-factor-via-gcd-asis-ctf-finals-2016).
- **DSA key recovery via MD5 collision on k-generation:** When nonce `k` derives from `MD5(prefix+counter)`, use `fastcoll` to produce MD5 prefix collision forcing nonce reuse, then standard private key recovery. See [ecc-attacks.md](ecc-attacks.md#dsa-key-recovery-via-md5-collision-on-k-generation-confidence-ctf-2017).
- **BB-84 QKD MITM:** Simulated BB-84 without authenticated classical channels allows full MITM -- independently negotiate keys with both parties, force constant value to one side. See [exotic-crypto-2.md](exotic-crypto-2.md#bb-84-quantum-key-distribution-mitm-attack-plaidctf-2017).

See [ecc-attacks.md](ecc-attacks.md), [advanced-math.md](advanced-math.md), and [exotic-crypto.md](exotic-crypto.md) for full code examples.

## Diffie-Hellman Attacks

- **Trivial g:** Try `g = 0, 1, p-1` and peer values `A = 0, 1, p-1, p` first; unvalidated range checks give known-constant secrets. See [dh-attacks.md](dh-attacks.md#trivial-generator-values-g--0-1-p-1).
- **Pohlig-Hellman:** Factor `p-1`; smooth means full DLP via BSGS per subgroup + CRT. See [dh-attacks.md](dh-attacks.md#pohlig-hellman-when-p-1-is-smooth).
- **Small-subgroup confinement / Lim-Lee:** Static key + composite `p-1` with small factors; send order-`r` element, brute `b mod r` via MAC/decrypt oracle, CRT across `r_i`. See [dh-attacks.md](dh-attacks.md#small-subgroup-confinement--lim-lee-static-key-recovery-via-crt).
- **X25519 low-order:** Cofactor 8 + clamping means small-order `u` forces all-zero `K`; `u = 0, 1` always probe. Missing all-zero check = 1-2 query break. See [ecc-attacks.md](ecc-attacks.md#x25519-low-order-points--all-zero-check-rfc-7748).

## Lattice / LWE Attacks

- **Quick triage:** If the challenge gives modular linear equations plus a promise that the hidden quantity is small, sparse, biased, or only partially leaked, treat it as a lattice candidate first. See [lattice-and-lwe.md](lattice-and-lwe.md#quick-triage-is-this-a-lattice-problem).
- **LLL / BKZ / Babai:** fpylll LLL.reduction / BKZ.reduction / GSO.Mat.babai / CVP.closest_vector (Sage Matrix(ZZ).LLL() / M.BKZ fallback in details) — start with LLL, move to BKZ when LLL almost works, use Babai for approximate CVP. See [lattice-and-lwe.md](lattice-and-lwe.md#core-tools-lll-bkz-babai-cvp-svp-asis-ctf-finals-2015-ctfzone-2017).
- **HNP from partial nonce leakage:** Partial or biased ECDSA/Schnorr nonces often reduce to Hidden Number Problem lattices; normalize equations, isolate bounded error, reduce, then brute-force the last few bits if needed. See [lattice-and-lwe.md](lattice-and-lwe.md#hidden-number-problem-hnp-partial-nonce--biased-nonce-nullcon-hackim-2020-ledger-donjon-ctf-2020).
- **Truncated LCG state recovery:** High-bit or low-bit leakage from affine recurrences is often just HNP in disguise; write each state as `observed * 2^t + hidden` and solve for the small hidden corrections. See [lattice-and-lwe.md](lattice-and-lwe.md#lcg-and-truncated-output-as-a-lattice-problem-x-mas-ctf-2018-fwordctf-2020).
- **LWE via CVP (Babai):** Construct lattice from `[q*I | 0; A^T | I]`, use fpylll GSO.Mat.babai or CVP.closest_vector to find closest vector, project to ternary {-1,0,1}. Watch for endianness mismatches between server description and actual encoding.
- **Ring-LWE / Module-LWE recognition:** Polynomial or negacyclic structure often looks scary but many CTFs weaken it with tiny coefficients, buggy representations, or enough leakage to flatten back into plain LWE. See [lattice-and-lwe.md](lattice-and-lwe.md#ring-lwe--module-lwe-recognition-notes-plaidctf-2016-dicectf-2022).
- **Orthogonal lattices:** Hidden subset or hidden subspace problems may need you to recover an orthogonal lattice first, then reconstruct the actual binary or short basis from its complement. See [lattice-and-lwe.md](lattice-and-lwe.md#orthogonal-lattices-hssp--ahssp-style-recovery-zer0pts-ctf-2022).
- **LLL for approximate GCD:** fpylll LLL.reduction (Sage Matrix(ZZ).LLL() fallback in details) — short vector in lattice reveals hidden factors
- **Subset sum / knapsack:** Binary knapsack and low-density subset-sum instances are still classic lattice territory; build the standard basis and look for a reduced row with a zero final coordinate. See [lattice-and-lwe.md](lattice-and-lwe.md#subset-sum--knapsack-via-lattice-reduction-hitcon-ctf-2017-backdoorctf-2023).
- **Multi-layer challenges:** Geometry → subspace recovery → LWE → AES-GCM decryption chain

See [advanced-math.md](advanced-math.md) for worked LWE solving code and [lattice-and-lwe.md](lattice-and-lwe.md) for attack selection, embeddings, and failure-mode triage.

## ZKP & Constraint Solving

- **ZKP cheating:** For impossible problems (3-coloring K4), find hash collisions or predict PRNG salts
- **Graph 3-coloring:** `nx.coloring.greedy_color(G, strategy='saturation_largest_first')`
- **Z3 solver:** BitVec for bit-level, Int for arbitrary precision; BPF/SECCOMP filter solving
- **Garbled circuits (free XOR):** XOR three truth table entries to recover global delta
- **Bigram substitution:** OR-Tools CP-SAT with automaton constraint for known plaintext structure
- **Trigram decomposition:** Positions mod n form independent monoalphabetic ciphers
- **Shamir SSS (deterministic coefficients):** One share + seeded RNG = univariate equation in secret
- **Race condition (TOCTOU):** Synchronized concurrent requests bypass `counter < N` checks
- **Groth16 broken setup (delta==gamma):** Trivially forge: A=alpha, B=beta, C=-vk_x. Always check verifier constants first
- **Groth16 proof replay:** Unconstrained nullifier + no tracking = infinite replays from setup tx
- **DV-SNARG forgery:** With verifier oracle access, learn secret v values from unconstrained pairs, forge via CRS entry cancellation
- **Shamir SSS reused polynomial coefficients:** When same random coefficients are used for every secret byte, subtracting shares cancels all randomness, leaving only plaintext differences. See [zkp-and-advanced.md](zkp-and-advanced.md#shamir-secret-sharing-with-reused-polynomial-coefficients-polictf-2017).

See [zkp-and-advanced.md](zkp-and-advanced.md) for full code examples and solver patterns.

## Modern Cipher Attacks (Additional)

- **Affine over composite modulus:** `c = A*x+b (mod M)`, M composite (e.g., 65=5*13). Chosen-plaintext recovery via one-hot vectors, CRT inversion per prime factor. See [modern-ciphers.md](modern-ciphers.md#affine-cipher-over-composite-modulus-nullcon-2026).
- **Custom linear MAC forgery:** XOR-based signature linear in secret blocks. Recover secrets from ~5 known pairs, forge for target. See [modern-ciphers.md](modern-ciphers.md#custom-linear-mac-forgery-nullcon-2026).
- **Manger oracle (RSA threshold):** RSA multiplicative + binary search on `m*s < 2^128`. ~128 queries to recover AES key.
- **AES key recovery via byte-by-byte zeroing oracle:** Integer overflow in key slot indexing allows selective byte zeroing; brute-force one byte at a time (256 per byte, 4096 total). See [modern-ciphers.md](modern-ciphers.md#aes-key-recovery-via-byte-by-byte-zeroing-oracle-confidence-ctf-2017).

## Introspective CRC via GF(2) Linear Algebra

Self-referential CRC: find ASCII string whose CRC equals itself. CRC is linear over GF(2), so the constraint becomes a solvable linear system. Free variables chosen for printable ASCII range. See [advanced-math.md](advanced-math.md#introspective-crc-via-gf2-linear-algebra-google-ctf-2017).

## CBC Padding Oracle Attack

Server reveals valid/invalid padding → decrypt any CBC ciphertext without key. ~4096 queries per 16-byte block. Use PadBuster or `padding-oracle` Python library. See [modern-ciphers.md](modern-ciphers.md#cbc-padding-oracle-attack).

## Bleichenbacher RSA Padding Oracle (ROBOT)

RSA PKCS#1 v1.5 padding validation oracle → adaptive chosen-ciphertext plaintext recovery. ~10K queries for RSA-2048. Affects TLS implementations via timing. See [modern-ciphers.md](modern-ciphers.md#bleichenbacher--pkcs1-v15-rsa-padding-oracle).

## Birthday Attack / Meet-in-the-Middle

n-bit hash collision in ~2^(n/2) attempts. Meet-in-the-middle breaks double encryption in O(2^k) instead of O(2^(2k)). See [modern-ciphers.md](modern-ciphers.md#birthday-attack--meet-in-the-middle).

- **Sponge hash MITM collision:** When sponge rate < state size, uncontrolled state bytes enable MITM — precompute forward encryptions keyed on uncontrolled bytes, search backward for matches. Reduces 2^48 to 2^24. See [modern-ciphers-3.md](modern-ciphers-3.md#sponge-hash-collision-via-meet-in-the-middle-on-partial-state-bkp-2017).

## CRC32 Collision-Based Signature Forgery (iCTF 2013)

CRC32 is linear — append 4 chosen bytes to force any target CRC32, forging `CRC32(msg || secret)` signatures without the secret. See [modern-ciphers.md](modern-ciphers.md#crc32-collision-based-signature-forgery-ictf-2013).

## Blum-Goldwasser Bit-Extension Oracle (PlaidCTF 2013)

Extend ciphertext by one bit per oracle query to leak plaintext via parity. Manipulate BBS squaring sequence to produce valid extended ciphertexts. See [modern-ciphers-2.md](modern-ciphers-2.md#blum-goldwasser-bit-extension-oracle-plaidctf-2013).

## Hash Length Extension Attack

Exploits Merkle-Damgard hashes (`hash(SECRET || user_data)`) — append arbitrary data and compute valid hash without knowing the secret. Use `hashpump` or `hashpumpy`. See [modern-ciphers-2.md](modern-ciphers-2.md#hash-length-extension-attack-plaidctf-2014).

## Compression Oracle (CRIME-Style)

Compression before encryption leaks plaintext via ciphertext length changes. Send chosen plaintexts; matching n-grams compress shorter. Same class as CRIME/BREACH. See [modern-ciphers-2.md](modern-ciphers-2.md#compression-oracle--crime-style-attack-bctf-2015).

## RC4 Second-Byte Bias

RC4's second output byte is biased toward `0x00` (probability 1/128 vs 1/256). Distinguishes RC4 from random with ~2048 samples. See [stream-ciphers.md](stream-ciphers.md#rc4-second-byte-bias-distinguisher-hackover-ctf-2015).

## RSA Multiplicative Homomorphism Signature Forgery

Unpadded RSA: `S(a) * S(b) mod n = S(a*b) mod n`. If oracle blacklists target message, sign its factors and multiply. See [rsa-attacks-2.md](rsa-attacks-2.md#rsa-signature-forgery-via-multiplicative-homomorphism-mma-ctf-2015).

## Common Patterns

- **RSA basics:** `phi = (p-1)*(q-1)`, `d = inverse(e, phi)`, `m = pow(c, d, n)`. See [rsa-attacks.md](rsa-attacks.md) for full examples.
- **XOR:** `from pwn import xor; xor(ct, key)`. See [classic-ciphers.md](classic-ciphers.md) for XOR variants.

## C srand/rand Prediction via ctypes (L3akCTF 2024, MireaCTF)

**Pattern:** Binary uses `srand(time(NULL))` + `rand()` for keys/XOR masks. Python's `random` module uses a different PRNG. Use `ctypes.CDLL('./libc.so.6')` to call C's `srand(int(time()))` and `rand()` directly, reproducing the exact sequence. See [prng.md](prng.md#c-srandrand-synchronization-via-python-ctypes) for XOR decryption examples and timing tips.

## V8 XorShift128+ (Math.random) State Recovery

**Pattern:** V8 JavaScript engine uses xs128p PRNG for `Math.random()`. Given 5-10 consecutive outputs of `Math.floor(CONST * Math.random())`, recover internal state (state0, state1) with Z3 QF_BV solver and predict future values. Values must be reversed (LIFO cache). Tool: `d0nutptr/v8_rand_buster`. See [prng.md](prng.md#v8-xorshift128-state-recovery-mathrandom-prediction).

## MT State Recovery from Float Outputs (PHD CTF Quals 2012)

**Pattern:** Server exposes `random.random()` floats. Standard untemper needs 624 × 32-bit integers, but floats yield only ~8 usable bits each. A precomputed GF(2) magic matrix (`not_random` library) recovers the full MT state from 3360+ float observations. Use to predict password reset tokens, session IDs, or CSRF tokens derived from `random.random()`. See [prng.md](prng.md#mt-state-recovery-from-randomrandom-floats-via-gf2-matrix-phd-ctf-quals-2012).

## Chaotic PRNG (Logistic Map)

- **Logistic map:** `x = r * x * (1 - x)`, `r ≈ 3.99-4.0`; seed recovery by brute-forcing high-precision decimals
- **Keystream:** `struct.pack("<f", x)` per iteration; XOR with ciphertext

See [prng.md](prng.md#logistic-map--chaotic-prng-seed-recovery-bypass-ctf-2025) for full code.

## SPN S-box Intersection Attack

Divide-and-conquer SPN key recovery: attack each S-box position independently, intersect valid key candidates across multiple plaintext-ciphertext pairs. Reduces exponential key space to independent sub-key searches. See [modern-ciphers-3.md](modern-ciphers-3.md#spn-cipher-partial-key-recovery-via-s-box-intersection-sharifctf-7-2016).

## Useful Tools

- **Python:** the image already has `pycryptodome`, `z3-solver`, `sympy`, and `gmpy2`
- **SageMath:** NOT in the image — collapsed Sage-only recipes are algorithm sketches; implement with sympy/gmpy2/pycryptodome per the linked pattern card's 工具对齐 line (see Attack Pattern Router below)
- **RsaCtfTool:** `RsaCtfTool -n <n> -e <e> --uncipher <c>` — automated RSA attack suite (tries Wiener, Hastad, Fermat, Pollard, and many more); add `--attack <name>` to force one
- **quipqiup.com:** Automated substitution cipher solver (frequency + word pattern analysis)

## Attack Pattern Router (Signal-First)

52 张攻击模式卡（36 attack / 8 primitive / 8 gap），从 Crypton 攻击库索引化抽取，卡片在 [patterns/](patterns/) 目录。**按题面信号查表，不按攻击名猜**：评测显示按名字关键词检索 recall@1 仅 5.8%，按信号加权检索 78.8%（评测套件见交付包 eval/）。

检索协议：
1. 从题面提取信号：指数大小、oracle 访问、值间关系、报错行为、密文结构
2. 下表按信号命中 2–3 行，读对应卡片（`patterns/<ID>.md`）
3. 用卡片「前置条件」核对实际数值——近邻 RSA 模式之间往往只差一条前置
4. 按「工具对齐（镜像真值）」节实现——卡片从不假设镜像外工具
5. 用卡片「验证」节自检通过后再提交
6. 标 `[G]` 的是声明缺口：走卡内替代路径，或明确向用户报告缺口

⚠️ 两条全局警示（适用于全部卡片）：
- 卡内引用的 source_code 只作算法参考，**禁止直接执行**（Python2/SageMath 时代产物，78 个脚本中 55 个 py3 解析失败）
- 数学公式为人工转录，使用前复核

### RSA (18)

| 题面信号 | 模式卡 |
|---|---|
| e 很小（3/5/7）且密文 c 明显小于 n；题目说明无填充 textbook RSA | [RSA-DIRECT-ROOT](patterns/RSA-DIRECT-ROOT.md) — RSA 小指数直接开根 |
| 题目提示 p 与 q 很接近 / 生成时用了 nextprime；n 能被快速平方差分解 | [RSA-FERMAT](patterns/RSA-FERMAT.md) — Fermat 分解（p、q 接近） |
| 题目说明素数由大量小因子乘积加 1 生成；p-1 是 B-smooth | [RSA-POLLARD-P1](patterns/RSA-POLLARD-P1.md) — Pollard p-1 分解（p-1 平滑） |
| 给了两个或更多模数 n1, n2, ...；题目提示素数生成器有故障 / 复用了素数 | [RSA-COMMON-PRIME](patterns/RSA-COMMON-PRIME.md) — 公共素因子攻击（多个 n 共享 p） |
| 同一明文用同一个 n、两个不同 e 加密得到 c1、c2；gcd(e1, e2) == 1 | [RSA-COMMON-MODULUS](patterns/RSA-COMMON-MODULUS.md) — 共模攻击（同 n 不同 e） |
| e 与 n 同量级（异常大，如 1024 位以上）；题目提示 d 很小 / 私钥生成有问题 | [RSA-WIENER](patterns/RSA-WIENER.md) — Wiener 攻击（小私钥指数 d） |
| 标准 Wiener 收敛项验不出来，但 e 仍然异常大；题目说明 d 比 N^0.25 大几个比特 | [RSA-WIENER-VARIANT](patterns/RSA-WIENER-VARIANT.md) — Wiener 变体（d 略超 N^0.25） |
| 同一明文用相同小 e 发给 k 个不同模数；k >= e | [RSA-HASTAD](patterns/RSA-HASTAD.md) — Hastad 广播攻击（同小 e、多个 n） |
| 每个接收者的明文是 M + a_i*常数 之类已知线性变换；小 e 广播但直接开根失败 | [RSA-HASTAD-PADDED](patterns/RSA-HASTAD-PADDED.md) — Hastad 广播 + 线性填充（Coppersmith 扩展） |
| 同一 (n,e) 下两条消息满足已知线性关系 M2 = f(M1)；题目给出 c1、c2 和关系式 | [RSA-FRANKLIN-REITER](patterns/RSA-FRANKLIN-REITER.md) — Franklin-Reiter 相关消息攻击 |
| 明文的绝大部分已知，只剩少量未知字节（如 flag 前缀）；c = (known + x)^e mod n，x 很小 | [RSA-COPPERSMITH-STEREOTYPED](patterns/RSA-COPPERSMITH-STEREOTYPED.md) — Coppersmith 定型消息攻击（已知明文高位） |
| 题目泄露了 p 的高位比特（通常需 >= 一半位长）；给了 p 的部分比特或近似值 | [RSA-COPPERSMITH-HIGHBITS](patterns/RSA-COPPERSMITH-HIGHBITS.md) — Coppersmith 已知 p 高位分解 n |
| 服务解密任意密文但只返回明文的最后一位（奇偶性）；允许选择密文查询 | [RSA-LSB-ORACLE](patterns/RSA-LSB-ORACLE.md) — RSA 最低位 oracle（二分恢复明文） |
| oracle 每次连接会更换 n；需要在断线后继续恢复剩余比特 | [RSA-LSB-ORACLE-VARIANT](patterns/RSA-LSB-ORACLE-VARIANT.md) — LSB oracle 变体（逐位、可跨会话续跑） |
| 题目提供加密 oracle 但隐藏 n；有时连 e 也不给 | [RSA-RETRIEVE-MODULUS](patterns/RSA-RETRIEVE-MODULUS.md) — 从加密 oracle 反推模数 n |
| PKCS#1 v1.5 签名验证不检查 0xFF 填充长度；e = 3 | [RSA-BLEICHENBACHER-E3](patterns/RSA-BLEICHENBACHER-E3.md) — e=3 Bleichenbacher 签名伪造 |
| 签名直接对 hash 做 m^d mod n，无填充；可获取任意消息的签名 | [RSA-UNPADDED-SIG-BLINDING](patterns/RSA-UNPADDED-SIG-BLINDING.md) — 无填充 RSA 签名乘性伪造（Blinding） |
| 题目给出签名和公钥，需要判断验证器是否严格；出现 DigestInfo / ASN.1 前缀 | [RSA-PKCS1-SIG-VERIFY](patterns/RSA-PKCS1-SIG-VERIFY.md) — PKCS#1 v1.5 签名填充结构与校验点 |

### 分组密码 (7)

| 题面信号 | 模式卡 |
|---|---|
| 只有一个加密黑盒，不知块大小与模式；题目第一步要求识别加密方式 | [BC-BLOCKSIZE-DETECT](patterns/BC-BLOCKSIZE-DETECT.md) — 分组长度与模式探测 |
| 服务把 secret 拼接在用户输入之后一起加密并返回密文；ECB 模式（相同明文块 → 相同密文块） | [BC-ECB-BYTE-AT-A-TIME](patterns/BC-ECB-BYTE-AT-A-TIME.md) — ECB 逐字节解密（加密 oracle 附加秘密） |
| 与 ECB 逐字节相同的加密 oracle（secret 拼在用户输入后）；同一明文块在不同位置得到不同密文块，每块依赖前一块密文（链接特性） | [BC-CBC-BYTE-AT-A-TIME](patterns/BC-CBC-BYTE-AT-A-TIME.md) — CBC 逐字节解密（加密 oracle 附加秘密） |
| 解密 oracle 可用但 IV 不公开；padding oracle 攻击解不出第一块 | [BC-CBC-IV-DETECT](patterns/BC-CBC-IV-DETECT.md) — CBC 未知 IV 恢复 |
| 服务端把用户输入拼进明文、过滤敏感字符后加密成 cookie；解密时直接信任 cookie 内容 | [BC-CBC-BIT-FLIPPING](patterns/BC-CBC-BIT-FLIPPING.md) — CBC 比特翻转（篡改 cookie 提权） |
| 服务端把 = 替换成 ? 之类字符过滤后再用 CTR 加密；CTR/流密码模式，密文与明文逐字节 XOR 对应 | [BC-CTR-BIT-FLIPPING](patterns/BC-CTR-BIT-FLIPPING.md) — CTR 比特翻转（流密码式篡改） |
| 服务对密文返回"填充正确/错误"两种可区分响应；报错信息、响应时间或 HTTP 状态码有差异 | [BC-CBC-PADDING-ORACLE](patterns/BC-CBC-PADDING-ORACLE.md) — CBC Padding Oracle Attack |

### MAC / 认证加密 (6)

| 题面信号 | 模式卡 |
|---|---|
| CBC-MAC 用于变长消息且 IV 固定；服务允许为任意消息生成 tag | [MAC-CBCMAC-FORGERY](patterns/MAC-CBCMAC-FORGERY.md) — CBC-MAC 变长消息伪造 |
| 已知 MAC(M1)，需要 M1／／M2 的合法 tag；服务拒绝直接对 M1／／M2 求 tag | [MAC-CBCMAC-LENGTH-EXT](patterns/MAC-CBCMAC-LENGTH-EXT.md) — CBC-MAC 长度扩展攻击 |
| 协议没有时间戳/nonce/序号；可截获合法 (消息, tag) 对 | [MAC-REPLAY](patterns/MAC-REPLAY.md) — MAC 重放攻击 |
| 同一 nonce/key 加密了两条不同消息，且都给出 tag；题目强调 nonce 重复或计数器回绕 | [AE-GCM-NONCE-REUSE](patterns/AE-GCM-NONCE-REUSE.md) — AES-GCM Forbidden Attack（nonce 重用） |
| 题目涉及 GCM tag 计算、关联数据 AAD；需要理解 H 与 J0 的作用 | [AE-GCM-INTERNALS](patterns/AE-GCM-INTERNALS.md) — AES-GCM / GHASH 结构 |
| 题目同时给出密文和 tag，需要判断组合顺序；存在解密前/后校验差异可用于 padding oracle | [AE-COMPOSITION](patterns/AE-COMPOSITION.md) — 认证加密组合方式判定 |

### 离散对数 / 椭圆曲线 / DH (10)

| 题面信号 | 模式卡 |
|---|---|
| 给定 g, h = g^x mod p，群阶很小；需要求 x | [DLP-BRUTE](patterns/DLP-BRUTE.md) — 离散对数暴力搜索 |
| 群阶为素数或不易分解，但规模中等；内存充足 | [DLP-BSGS](patterns/DLP-BSGS.md) — Baby-Step Giant-Step 求 DLP |
| 群阶为素数；内存受限，不能用 BSGS | [DLP-POLLARD-RHO](patterns/DLP-POLLARD-RHO.md) — Pollard's Rho 求 DLP（素数阶） |
| 群阶 n 可分解为小素数幂；p-1 是 smooth number | [DLP-POHLIG-HELLMAN](patterns/DLP-POHLIG-HELLMAN.md) — Pohlig-Hellman（平滑阶群） |
| 给定椭圆曲线基点 P 与 Q = x*P；基点阶为中等规模素数 | [ECDLP-BSGS](patterns/ECDLP-BSGS.md) — ECDLP 的 Baby-Step Giant-Step |
| 基点阶为素数时需要唯一解；内存受限 | [ECDLP-POLLARD-RHO](patterns/ECDLP-POLLARD-RHO.md) — ECDLP 的 Pollard's Rho |
| 题目给出自定义曲线参数 a, b, p；需要自己实现点运算 | [EC-POINT-ARITH](patterns/EC-POINT-ARITH.md) — 椭圆曲线点运算基础 |
| DH 生成元 g 的阶含小因子（p-1 平滑）；可反复向对方发送自己的公钥并观察共享密钥/MAC | [DH-SMALL-SUBGROUP](patterns/DH-SMALL-SUBGROUP.md) — Small Subgroup Confinement Attack |
| ECDH 服务端不校验收到的点是否落在约定曲线上；可多次提交自选点并观察结果 | [ECDH-INVALID-CURVE](patterns/ECDH-INVALID-CURVE.md) — Invalid Curve Point Attack |
| 基于椭圆曲线的挑战-响应身份认证；验证器只检查单个响应值 | [ID-EPHEMERAL-FORGERY](patterns/ID-EPHEMERAL-FORGERY.md) — 临时密钥身份认证的伪造与作弊检测 |

### 签名 / ElGamal (3)

| 题面信号 | 模式卡 |
|---|---|
| 两条不同消息的签名具有相同的 r；题目暗示签名随机数生成器有问题 | [ECDSA-K-REUSE](patterns/ECDSA-K-REUSE.md) — ECDSA nonce(k) 重用恢复私钥 |
| 题目给出 (p, g, y) 与签名 (r, s)；需要验证 pow(g,h,p) == pow(r,s,p)*pow(y,r,p) mod p | [ELGAMAL-SIG](patterns/ELGAMAL-SIG.md) — ElGamal 签名方案结构 |
| 密文是 (c1, c2) 一对；题目给出群 p、生成元 g、公钥 | [ELGAMAL-ENC](patterns/ELGAMAL-ENC.md) — ElGamal 加密与不安全生成元 |

### GAP 声明缺口 (8)

| 题面信号 | 模式卡 |
|---|---|
| Wiener 失败但 d 仍偏小；e 接近 n 且 d < N^0.292 | **[G]** [GAP-BONEH-DURFEE](patterns/GAP-BONEH-DURFEE.md) — Boneh-Durfee 攻击（d < N^0.292） |
| RSA 解密服务返回"填充是否合法"；题目是 CCA 型 oracle | **[G]** [GAP-PKCS1-PADDING-ORACLE](patterns/GAP-PKCS1-PADDING-ORACLE.md) — PKCS#1 v1.5 加密填充 oracle |
| 题目基于可预测的伪随机数生成器；给出若干连续输出要求预测下一个 | **[G]** [GAP-PRNG](patterns/GAP-PRNG.md) — PRNG 预测（LCG / Mersenne Twister / LFSR） |
| 题目出现格、LWE、高维向量、背包；Coppersmith 之外的 small_roots 场景 | **[G]** [GAP-LATTICE](patterns/GAP-LATTICE.md) — 格密码与 LLL（LWE / NTRU / 背包） |
| MAC = hash(secret ／／ message)，secret 长度已知；需要为追加内容生成合法 MAC | **[G]** [GAP-HASH-LENGTH-EXT](patterns/GAP-HASH-LENGTH-EXT.md) — Merkle-Damgård 哈希长度扩展 |
| 多条签名，nonce 的高位/低位已知或固定；r 值各不相同但存在偏置 | **[G]** [GAP-ECDSA-NONCE-BIAS](patterns/GAP-ECDSA-NONCE-BIAS.md) — ECDSA nonce 部分泄露 / 偏置（格攻击） |
| 同一消息得到一条正确签名和一条错误签名；题目提示签名时发生了一次计算错误 | **[G]** [GAP-CRT-FAULT](patterns/GAP-CRT-FAULT.md) — RSA-CRT 故障攻击（Bellcore） |
| 题目是字节流、频率分析、重复密钥 XOR；入门级 crypto 题 | **[G]** [GAP-CLASSIC-XOR](patterns/GAP-CLASSIC-XOR.md) — 经典/XOR/编码类密码 |

