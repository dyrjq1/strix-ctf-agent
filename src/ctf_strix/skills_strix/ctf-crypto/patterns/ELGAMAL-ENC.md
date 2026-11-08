# ELGAMAL-ENC — ElGamal 加密与不安全生成元

> kind=primitive · category=Signature-ElGamal · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=example.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 密文是 (c1, c2) 一对
- 题目给出群 p、生成元 g、公钥

## 给定
- p
- g
- y
- c1
- c2

## 前置条件
- 基于 DLP

## 目标
解密或识别小子群缺陷

## 算法步骤（来自 Crypton，算法层面）
1. c1 = g^k, c2 = m * y^k
2. m = c2 * (c1^x)^-1 mod p
3. 检查 p 是否 safe prime 或 g 是否生成素数阶子群

## 验证
重新加密 m 可复现 c2（k 相同时）

## 陷阱
- Crypton 明确警告：群不是 safe prime 且 g 不生成素数阶子群时易受 Small Subgroup Attack
- 实现标注为 python-2.7

## 工具对齐（镜像真值）
python3 + sympy.discrete_log。

交叉引用：advanced-math.md、exotic-crypto-2.md、exotic-crypto.md

相关模式：DH-SMALL-SUBGROUP

原始文档：Elgamal-Encryption/README.md
