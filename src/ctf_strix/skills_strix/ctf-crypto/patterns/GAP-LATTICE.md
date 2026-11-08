# GAP-LATTICE — [缺口] 格密码与 LLL（LWE / NTRU / 背包）

> kind=gap · category=GAP · status=gap · source=ashutosh1206/Crypton@master
>
> ⚠️ **缺口条目**：Crypton 未实现/未文档化此攻击。本卡给出镜像内可行的替代路径与既有部分覆盖；命中即应考虑向用户声明缺口，不要硬套近似攻击。

## 信号（题面可观测）
- 题目出现格、LWE、高维向量、背包
- Coppersmith 之外的 small_roots 场景

## 给定
- 格基或线性同余方程组

## 前置条件
- 存在短向量

## 目标
用 LLL/BKZ 找短向量

## 算法步骤（来自 Crypton，算法层面）
1. Crypton 仅在 Coppersmith 里间接提到 LLL，无独立章节
2. 需外部资料：fpylll / SageMath / CryptoHack Lattice 章节

## 验证
找到满足约束的短向量

## 陷阱
- 2018 年后的 CTF 中占比显著上升，是本知识库最大盲区

## 工具对齐（镜像真值）
镜像无 fpylll/SageMath——advanced-math.md 的 LLL 代码依赖 fpylll（from fpylll import …），只能作伪码参考；镜像路径：用 python3 按 LLL 伪码现写实现（几十行量级）再跑本题构造的矩阵，写不出则向用户声明缺口。

交叉引用：advanced-math.md、ecc-attacks.md、lattice-and-lwe.md

相关模式：RSA-COPPERSMITH-STEREOTYPED
