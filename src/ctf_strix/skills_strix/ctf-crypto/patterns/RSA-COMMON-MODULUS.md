# RSA-COMMON-MODULUS — 共模攻击（同 n 不同 e）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=exploit.py:py3-ok — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 同一明文用同一个 n、两个不同 e 加密得到 c1、c2
- gcd(e1, e2) == 1

## 给定
- n
- e1
- e2
- c1
- c2

## 前置条件
- gcd(e1,e2)=1
- 无填充
- 同一明文同一模数

## 目标
不用分解 n 直接恢复 m

## 算法步骤（来自 Crypton，算法层面）
1. 扩展欧几里得求 a,b 使 a*e1 + b*e2 = 1
2. m = pow(c1, a, n) * pow(c2, b, n) mod n（a 或 b 为负时先求模逆）
3. 若 gcd(e1,e2)=g>1，还需对结果开 g 次根

## 验证
pow(m, e1, n) == c1 and pow(m, e2, n) == c2

## 陷阱
- 负指数必须用 modular inverse，不能直接 pow(c, -3, n)（Python 3.8+ 支持但需注意语义）
- gcd(e1,e2) > 1 时结果不是 m 而是 m^g

## 工具对齐（镜像真值）
python3 + gmpy2.invert 联立同模方程；rsa-attacks.md 有现成实现。

交叉引用：rsa-attacks-2.md、rsa-attacks.md

相关模式：RSA-DIRECT-ROOT、RSA-HASTAD

原始文档：RSA-encryption/Attack-Common-Modulus/README.md
