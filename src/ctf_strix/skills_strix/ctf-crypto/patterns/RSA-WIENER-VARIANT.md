# RSA-WIENER-VARIANT — Wiener 变体（d 略超 N^0.25）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=exploit.py:py3-fail+requires-sage — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 标准 Wiener 收敛项验不出来，但 e 仍然异常大
- 题目说明 d 比 N^0.25 大几个比特

## 给定
- n
- e

## 前置条件
- d 仅比 N^0.25 略大

## 目标
恢复 d

## 算法步骤（来自 Crypton，算法层面）
1. 取 e/n 连分数的第 m 与 m+1 个收敛项
2. 枚举形如 (r*k_{m+1} + k_m)/(r*d_{m+1} + d_m) 的候选 d
3. 逐个用 pow(2, e*d, n) == 2 验证

## 验证
pow(2, e*d, n) == 2

## 陷阱
- 搜索空间比标准 Wiener 大，需要限制 r 的上界
- 再大就该用 Boneh-Durfee（Crypton 列为 TODO，未实现）

## 工具对齐（镜像真值）
python3 手写连分数变体（Wiener 边界外的扩展）；无现成 CLI，参考 rsa-attacks.md 连分数实现改造。

交叉引用：rsa-attacks-2.md、rsa-attacks.md

相关模式：RSA-WIENER、GAP-BONEH-DURFEE

原始文档：RSA-encryption/Attack-Wiener-variant/README.md
