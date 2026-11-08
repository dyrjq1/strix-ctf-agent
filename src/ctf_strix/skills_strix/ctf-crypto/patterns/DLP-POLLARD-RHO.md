# DLP-POLLARD-RHO — Pollard's Rho 求 DLP（素数阶）

> kind=attack · category=DLP-EC-DH · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=pollardrho.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 群阶为素数
- 内存受限，不能用 BSGS

## 给定
- g
- h
- p
- n

## 前置条件
- n 为素数时可得到唯一解

## 目标
O(sqrt(n)) 时间、O(1) 空间求 x

## 算法步骤（来自 Crypton，算法层面）
1. 用随机游走构造 (a,b) 使 g^a h^b
2. Floyd 判圈找碰撞
3. 由碰撞方程解 x，需 gcd 可逆

## 验证
pow(g, x, p) == h

## 陷阱
- 群阶合数时可能得到多解
- Crypton 文档极短，只给了 Handbook of Applied Cryptography 的章节指引

## 工具对齐（镜像真值）
python3 手写 rho（存储省但成本高，先试 BSGS/Pohlig）。

交叉引用：exotic-crypto-2.md、rsa-attacks-2.md、rsa-attacks.md

相关模式：DLP-BSGS、ECDLP-POLLARD-RHO

原始文档：Discrete-Logarithm-Problem/Algo-Pollard-Rho/README.md
