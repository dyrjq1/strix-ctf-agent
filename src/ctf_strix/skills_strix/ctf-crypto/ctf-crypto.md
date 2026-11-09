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
or pure Python instead (hash length extension: ready-made stdlib `sha_extend`
recipe in [ctf-misc/ctf-misc.md](../ctf-misc/ctf-misc.md)).

**Offline image: no installs and no internet.** `python3` ships `gmpy2`,
`sympy` and `z3-solver` (so no libgmp build step is needed); `RsaCtfTool` is
installed (offline, no factordb by default); `hashcat` and SageMath are not
available -- [advanced-math.md](advanced-math.md) Coppersmith pseudocode (its
LLL step needs fpylll, not in the image: hand-write LLL in python3) and
pure-Python attacks.

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


**Deep-dive map** (sections moved verbatim under the 8KB gate; `exec_command` reads them, do NOT `load_skill`):
- [archive-deep-dive.md](archive-deep-dive.md): Additional Resources + classic/modern cipher, RSA/EC/DH/lattice/ZKP/PRNG technique notes
- [router-tables.md](router-tables.md): signal tables of the 52-card Attack Pattern Router (6 families); then read the matched card at `patterns/<ID>.md`
