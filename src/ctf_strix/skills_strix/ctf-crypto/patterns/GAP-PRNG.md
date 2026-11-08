# GAP-PRNG — [缺口] PRNG 预测（LCG / Mersenne Twister / LFSR）

> kind=gap · category=GAP · status=gap · source=ashutosh1206/Crypton@master
>
> ⚠️ **缺口条目**：Crypton 未实现/未文档化此攻击。本卡给出镜像内可行的替代路径与既有部分覆盖；命中即应考虑向用户声明缺口，不要硬套近似攻击。

## 信号（题面可观测）
- 题目基于可预测的伪随机数生成器
- 给出若干连续输出要求预测下一个

## 给定
- PRNG 输出序列

## 前置条件
- 状态可反推

## 目标
恢复内部状态

## 算法步骤（来自 Crypton，算法层面）
1. Crypton TODO 明确列出这三项但从未实现
2. 需外部资料或自行实现

## 验证
预测下一组输出与服务端一致

## 陷阱
- 这是现代 CTF crypto 的高频题型，Crypton 完全缺失

## 工具对齐（镜像真值）
部分覆盖：prng-attacks.md / prng.md（MT19937、浮点输出恢复状态、srand 预测）；未覆盖子型按卡内算法 python3 现写。

交叉引用：lattice-and-lwe.md、post-quantum.md、prng-attacks.md

