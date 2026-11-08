# RSA-LSB-ORACLE-VARIANT — LSB oracle 变体（逐位、可跨会话续跑）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=lsbitoracle-variant.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- oracle 每次连接会更换 n
- 需要在断线后继续恢复剩余比特
- 查询次数约等于明文比特数

## 给定
- n
- e
- c
- LSB oracle

## 前置条件
- 无填充 RSA
- 每轮可重新获取 n

## 目标
恢复明文，且对会话重启鲁棒

## 算法步骤（来自 Crypton，算法层面）
1. 每轮维护已恢复的部分比特 a_i
2. 按位构造查询密文并读取 oracle 位
3. 服务重启后直接从上一次的 a_i 继续，不必从头开始

## 验证
pow(m, e, n_original) == c

## 陷阱
- 复杂度是明文比特数而非 log2(n)，查询量更大
- 与二分法不可混用，重新推导递推式

## 工具对齐（镜像真值）
同上，纯 python3 二分。

交叉引用：exotic-crypto-2.md、modern-ciphers-2.md、modern-ciphers-3.md

相关模式：RSA-LSB-ORACLE

原始文档：RSA-encryption/Attack-LSBit-Oracle-variant/README.md
