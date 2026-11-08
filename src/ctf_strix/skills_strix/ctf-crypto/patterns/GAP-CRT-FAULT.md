# GAP-CRT-FAULT — [缺口] RSA-CRT 故障攻击（Bellcore）

> kind=gap · category=GAP · status=gap · source=ashutosh1206/Crypton@master
>
> ⚠️ **缺口条目**：Crypton 未实现/未文档化此攻击。本卡给出镜像内可行的替代路径与既有部分覆盖；命中即应考虑向用户声明缺口，不要硬套近似攻击。

## 信号（题面可观测）
- 同一消息得到一条正确签名和一条错误签名
- 题目提示签名时发生了一次计算错误

## 给定
- m
- s_correct
- s_faulty
- e
- n

## 前置条件
- 使用 CRT 优化的签名实现

## 目标
gcd(s_faulty^e - m, n) 分解 n

## 算法步骤（来自 Crypton，算法层面）
1. Crypton 未覆盖
2. 需外部资料：Bellcore fault attack

## 验证
p*q == n

## 陷阱
- 只适用于 CRT 实现

## 工具对齐（镜像真值）
实现简单：python3 求 gcd(σ − σ_p) 恢复 p（无符号故障差 gcd）；ecc-attacks.md 有 fault 小节。

交叉引用：advanced-math.md、dh-attacks.md、ecc-attacks.md

相关模式：RSA-FERMAT
