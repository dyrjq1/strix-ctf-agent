# DLP-BRUTE — 离散对数暴力搜索

> kind=primitive · category=DLP-EC-DH · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=brute.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 给定 g, h = g^x mod p，群阶很小
- 需要求 x

## 给定
- g
- h
- p
- 群阶 n

## 前置条件
- n 足够小

## 目标
求 x

## 算法步骤（来自 Crypton，算法层面）
1. 枚举 x 计算 pow(g, x, p) 与 h 比较
2. 阶较大时改用 BSGS / Pollard rho / Pohlig-Hellman

## 验证
pow(g, x, p) == h

## 陷阱
- 先判断群阶结构再选算法，不要一律暴力
- 本目录是 DLP 基础，含循环群定义

## 工具对齐（镜像真值）
python3 pow 枚举。

交叉引用：advanced-math.md、ecc-attacks.md、exotic-crypto-2.md

相关模式：DLP-BSGS、DLP-POLLARD-RHO、DLP-POHLIG-HELLMAN

原始文档：Discrete-Logarithm-Problem/README.md
