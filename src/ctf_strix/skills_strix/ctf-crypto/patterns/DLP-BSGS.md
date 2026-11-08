# DLP-BSGS — Baby-Step Giant-Step 求 DLP

> kind=attack · category=DLP-EC-DH · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=bsgs.py:py3-fail+requires-sage — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 群阶为素数或不易分解，但规模中等
- 内存充足

## 给定
- g
- h
- p
- n

## 前置条件
- 已知群阶 n

## 目标
O(sqrt(n)) 时间求 x

## 算法步骤（来自 Crypton，算法层面）
1. m = ceil(sqrt(n))，令 x = i*m + j
2. 存表 g^j（baby steps）
3. 枚举 i 检查 h * g^(-i*m) 是否在表中
4. 命中即 x = i*m + j

## 验证
pow(g, x, p) == h

## 陷阱
- 空间复杂度也是 O(sqrt(n))，大阶时会 OOM
- Crypton 指出同复杂度的 Pollard rho 更省空间

## 工具对齐（镜像真值）
sympy.discrete_log（内置 BSGS/Pohlig-Hellman 自动选择）或手写 BSGS；dh-attacks.md。

交叉引用：advanced-math.md、dh-attacks.md、ecc-attacks.md

相关模式：DLP-POLLARD-RHO、ECDLP-BSGS

原始文档：Discrete-Logarithm-Problem/Algo-Baby-Step-Giant-Step/README.md
