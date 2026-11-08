# GAP-ECDSA-NONCE-BIAS — [缺口] ECDSA nonce 部分泄露 / 偏置（格攻击）

> kind=gap · category=GAP · status=gap · source=ashutosh1206/Crypton@master
>
> ⚠️ **缺口条目**：Crypton 未实现/未文档化此攻击。本卡给出镜像内可行的替代路径与既有部分覆盖；命中即应考虑向用户声明缺口，不要硬套近似攻击。

## 信号（题面可观测）
- 多条签名，nonce 的高位/低位已知或固定
- r 值各不相同但存在偏置

## 给定
- 多组 (r, s, h) 与 nonce 部分信息

## 前置条件
- 偏置足够大

## 目标
构造 HNP 用 LLL 恢复私钥

## 算法步骤（来自 Crypton，算法层面）
1. Crypton 只覆盖 k 完全重用的情形
2. 需外部资料：Hidden Number Problem + LLL

## 验证
dA*G == 公钥

## 陷阱
- 比 k-reuse 更常见，务必另找资料

## 工具对齐（镜像真值）
无现成脚本；HNP + advanced-math.md 的 LLL 现场构造（难度高，先估偏置可解性再动手）。

交叉引用：advanced-math.md、ecc-attacks.md、lattice-and-lwe.md

相关模式：ECDSA-K-REUSE、GAP-LATTICE
