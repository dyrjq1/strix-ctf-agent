# RSA-FERMAT — Fermat 分解（p、q 接近）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=fermat.sage:sage-script — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 题目提示 p 与 q 很接近 / 生成时用了 nextprime
- n 能被快速平方差分解
- 出现 qproximity 类题面

## 给定
- n

## 前置条件
- |p - q| 约小于 N^(1/4)

## 目标
分解 n 得到 p、q

## 算法步骤（来自 Crypton，算法层面）
1. a = isqrt(n) 向上取整
2. b2 = a*a - n，检查 b2 是否完全平方
3. 若是则 p = a - sqrt(b2), q = a + sqrt(b2)；否则 a += 1 重复
4. 分解后 d = inverse(e, (p-1)(q-1))

## 验证
p * q == n 且 isprime(p) 且 isprime(q)

## 陷阱
- 朴素循环在差距稍大时极慢，可加 sieve 改进（Crypton TODO 未完成）
- p、q 差距大时不要用；镜像无 ECM/CADO-NFS，改走 RsaCtfTool 全攻击面（见工具对齐）

## 工具对齐（镜像真值）
python3 + gmpy2.isqrt 手写 Fermat 迭代（p、q 接近时快）；或 RsaCtfTool --attack fermat。原库的 cado-nfs/ECM 大合数路径镜像没有——大 n 时改走 RsaCtfTool 全攻击面，仍不行则声明缺口。

交叉引用：exotic-crypto-2.md、modern-ciphers.md、rsa-attacks-2.md

相关模式：RSA-POLLARD-P1、RSA-COMMON-PRIME

原始文档：RSA-encryption/Factorisation-Fermat/README.md
