# ECDLP-BSGS — ECDLP 的 Baby-Step Giant-Step

> kind=attack · category=DLP-EC-DH · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=bsgs_ecdlp.py:py3-fail+requires-sage — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 给定椭圆曲线基点 P 与 Q = x*P
- 基点阶为中等规模素数

## 给定
- 曲线参数
- P
- Q
- n

## 前置条件
- 已知子群阶 n

## 目标
O(sqrt(n)) 求标量 x

## 算法步骤（来自 Crypton，算法层面）
1. m = ceil(sqrt(n))，x = i*m + j
2. 存表 j*P
3. 枚举 i 查 Q - i*m*P
4. 命中得 x

## 验证
x*P == Q

## 陷阱
- 点运算需正确处理无穷远点
- 空间开销 O(sqrt(n))

## 工具对齐（镜像真值）
python3 手写 EC 点算术 + BSGS；ecc-attacks.md 有 sage 改写实现。

交叉引用：advanced-math.md、dh-attacks.md、ecc-attacks.md

相关模式：DLP-BSGS、ECDLP-POLLARD-RHO

原始文档：Discrete-Logarithm-Problem/Elliptic-Curve-DLP/Algo-Baby-Step-Giant-Step/README.md
