# RSA-HASTAD — Hastad 广播攻击（同小 e、多个 n）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=hastad_unpadded.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 同一明文用相同小 e 发给 k 个不同模数
- k >= e
- 给了多组 (n_i, c_i)

## 给定
- e
- (n_i, c_i) 至少 e 组

## 前置条件
- k >= e
- 各 n_i 两两互素
- 无填充

## 目标
恢复 m

## 算法步骤（来自 Crypton，算法层面）
1. CRT 合并得到 C = m^e mod (n1*n2*...*nk)
2. 因 m^e < 乘积，直接对 C 开 e 次整数根
3. 若某对 gcd(ni,nj) != 1，先转公共素因子攻击

## 验证
pow(m, e, n_i) == c_i 对所有 i 成立

## 陷阱
- n_i 不互素时 CRT 不成立，先做 pairwise gcd
- 有线性填充时需用 Coppersmith 版（见下一条）

## 工具对齐（镜像真值）
sympy.ntheory.modular.crt + gmpy2.iroot，纯 python3。

交叉引用：rsa-attacks-2.md、rsa-attacks.md、modern-ciphers-3.md

相关模式：RSA-COMMON-PRIME、RSA-HASTAD-PADDED、RSA-DIRECT-ROOT

原始文档：RSA-encryption/Attack-Hastad-Broadcast/README.md
