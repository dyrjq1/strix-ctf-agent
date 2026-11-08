# GAP-BONEH-DURFEE — [缺口] Boneh-Durfee 攻击（d < N^0.292）

> kind=gap · category=GAP · status=gap · source=ashutosh1206/Crypton@master
>
> ⚠️ **缺口条目**：Crypton 未实现/未文档化此攻击。本卡给出镜像内可行的替代路径与既有部分覆盖；命中即应考虑向用户声明缺口，不要硬套近似攻击。

## 信号（题面可观测）
- Wiener 失败但 d 仍偏小
- e 接近 n 且 d < N^0.292

## 给定
- n
- e

## 前置条件
- d 小于 N^0.292

## 目标
用格约简恢复 d

## 算法步骤（来自 Crypton，算法层面）
1. Crypton README 的 TODO 里列为待实现，仓库中无文档与代码
2. 需外部资料：Boneh-Durfee 论文 / SageMath small_roots 实现

## 验证
pow(2, e*d, n) == 2

## 陷阱
- 不要误以为 Crypton 覆盖了该攻击

## 工具对齐（镜像真值）
真缺口：镜像无现成双变量 Coppersmith。最近路径 = advanced-math.md 的 LLL 基础件现场推导，或先试 RSA-WIENER-VARIANT；超出能力时向用户声明缺口。

交叉引用：rsa-attacks.md、rsa-attacks-2.md

相关模式：RSA-WIENER
