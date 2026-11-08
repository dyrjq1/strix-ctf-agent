# ECDLP-POLLARD-RHO — ECDLP 的 Pollard's Rho

> kind=attack · category=DLP-EC-DH · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=pollardrho.py:py3-fail+requires-sage — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 基点阶为素数时需要唯一解
- 内存受限

## 给定
- 曲线参数
- P
- Q
- n

## 前置条件
- n 为素数（否则多解）

## 目标
求标量 x

## 算法步骤（来自 Crypton，算法层面）
1. 定义分区函数（按点的 x 坐标划分）与随机游走 a*P + b*Q
2. 用 Floyd 判圈找 (a,b) 与 (A,B) 的碰撞
3. x = (a - A) * inverse(B - b, n) mod n，要求 gcd(B-b, n) == 1
4. 若 gcd 不为 1 则重新选取初始对

## 验证
x * P == Q

## 陷阱
- gcd(B-b, n) != 1 时需重新随机化初始对
- 群阶为合数时解不唯一

## 工具对齐（镜像真值）
python3 手写 rho（成本高，先 BSGS）。

交叉引用：exotic-crypto-2.md、rsa-attacks-2.md、rsa-attacks.md

相关模式：ECDLP-BSGS、EC-POINT-ARITH

原始文档：Discrete-Logarithm-Problem/Elliptic-Curve-DLP/Algo-Pollard-Rho/README.md
