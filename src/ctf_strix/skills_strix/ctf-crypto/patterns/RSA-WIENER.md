# RSA-WIENER — Wiener 攻击（小私钥指数 d）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=exploit.py:py3-fail+requires-sage — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- e 与 n 同量级（异常大，如 1024 位以上）
- 题目提示 d 很小 / 私钥生成有问题

## 给定
- n
- e

## 前置条件
- d < N^0.25 / 3
- q < p < 2q

## 目标
恢复 d 并分解 n

## 算法步骤（来自 Crypton，算法层面）
1. 展开 e/n 的连分数，枚举所有收敛项 k/d
2. 对每个候选 d，用已知明文检验 pow(pow(m,e,n),d,n) == m
3. 或者用 ed-1 = k*phi 反推 phi 再解 p+q

## 验证
pow(2, e*d, n) == 2 或 pow(pow(m,e,n),d,n) == m

## 陷阱
- Crypton 的 exploit.py 硬编码 m=12345 自测，不是通用函数
- d 略大于界时改用 Wiener 变体或 Boneh-Durfee（本仓库缺）

## 工具对齐（镜像真值）
RsaCtfTool --attack wiener 一发；或 python3 手写连分数（rsa-attacks.md 的实现可在镜像内直接跑）。

交叉引用：rsa-attacks-2.md、rsa-attacks.md

相关模式：RSA-WIENER-VARIANT、GAP-BONEH-DURFEE

备注：验证候选 d 时不要依赖原仓库脚本，见其 source_code 状态。

原始文档：RSA-encryption/Attack-Wiener/README.md
