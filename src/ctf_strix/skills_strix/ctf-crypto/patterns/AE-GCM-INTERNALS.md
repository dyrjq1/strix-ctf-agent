# AE-GCM-INTERNALS — AES-GCM / GHASH 结构

> kind=primitive · category=MAC-AE · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=AES-GCM-implementation.py:py3-ok — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 题目涉及 GCM tag 计算、关联数据 AAD
- 需要理解 H 与 J0 的作用

## 给定
- n
- key
- nonce

## 前置条件
- GF(2^128) 上的多项式乘法

## 目标
为 nonce 重用 / tag 伪造提供数学基础

## 算法步骤（来自 Crypton，算法层面）
1. E_K(J0) 生成 CTR 初值
2. GHASH 在 GF(2^128) 上按块乘 H 累加
3. tag = GHASH xor E_K(J0)

## 验证
与标准测试向量吻合

## 陷阱
- Crypton 的 AES-GCM 实现有已知 bug（issue #5 未修），不要作为参考实现
- 公式多为 gif 图片，纯文本检索不到

## 工具对齐（镜像真值）
python3 手写 GF(2^128) 乘法（GHASH 本体），无外部依赖。

交叉引用：modern-ciphers-2.md、modern-ciphers-4.md、modern-ciphers.md

相关模式：AE-GCM-NONCE-REUSE

原始文档：Authenticated-Encryption/AES-GCM/README.md
