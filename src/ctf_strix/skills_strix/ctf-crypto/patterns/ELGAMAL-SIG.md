# ELGAMAL-SIG — ElGamal 签名方案结构

> kind=primitive · category=Signature-ElGamal · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=example.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 题目给出 (p, g, y) 与签名 (r, s)
- 需要验证 pow(g,h,p) == pow(r,s,p)*pow(y,r,p) mod p

## 给定
- p
- g
- y
- r
- s

## 前置条件
- 基于 DLP 的循环群

## 目标
理解/验证签名，识别随机数复用风险

## 算法步骤（来自 Crypton，算法层面）
1. 密钥生成 x，y = g^x mod p
2. 签名选随机 k，r = g^k, s 由 h = x*r + k*s 解出
3. 验证等式 pow(g,h,p) == pow(r,s,p)*pow(y,r,p) mod p

## 验证
验证等式成立

## 陷阱
- Crypton 示例用 md5 且为 Python 2，仅作结构参考
- k 复用会直接泄露私钥，与 ECDSA 同理

## 工具对齐（镜像真值）
python3 手写（pow + 模逆）。

交叉引用：advanced-math.md、exotic-crypto-2.md、exotic-crypto.md

相关模式：ECDSA-K-REUSE、DLP-BRUTE

原始文档：Digital-Signatures/ElGamal-Signatures/README.md
