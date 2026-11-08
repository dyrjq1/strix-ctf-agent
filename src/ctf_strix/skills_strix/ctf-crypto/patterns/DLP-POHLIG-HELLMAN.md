# DLP-POHLIG-HELLMAN — Pohlig-Hellman（平滑阶群）

> kind=attack · category=DLP-EC-DH · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=ph_orderp2.py:py3-fail; ph_orderpp.py:py3-fail; pohlig_hellman.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 群阶 n 可分解为小素数幂
- p-1 是 smooth number

## 给定
- g
- h
- p
- n 的分解

## 前置条件
- n-smooth

## 目标
把 DLP 拆到各个小素数幂子群再 CRT 合并

## 算法步骤（来自 Crypton，算法层面）
1. 分三种情形：n = 2^e / n = p^e / 一般 n = prod p_i^e_i
2. 在每个子群求 x mod p_i^e_i
3. CRT 合并得到 x mod n

## 验证
pow(g, x, p) == h

## 陷阱
- 2020 年最后一次提交就是修这个算法的实现（Fixes #8）
- 与非平滑阶的 Pollard rho 互补

## 工具对齐（镜像真值）
sympy.discrete_log 自动分圆；或 python3 手写逐子群 BSGS。

交叉引用：advanced-math.md、dh-attacks.md、ecc-attacks.md

相关模式：DLP-BSGS、DH-SMALL-SUBGROUP、RSA-POLLARD-P1

原始文档：Discrete-Logarithm-Problem/Algo-Pohlig-Hellman/README.md
