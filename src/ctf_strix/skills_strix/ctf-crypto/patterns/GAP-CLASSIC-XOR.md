# GAP-CLASSIC-XOR — [缺口] 经典/XOR/编码类密码

> kind=gap · category=GAP · status=gap · source=ashutosh1206/Crypton@master
>
> ⚠️ **缺口条目**：Crypton 未实现/未文档化此攻击。本卡给出镜像内可行的替代路径与既有部分覆盖；命中即应考虑向用户声明缺口，不要硬套近似攻击。

## 信号（题面可观测）
- 题目是字节流、频率分析、重复密钥 XOR
- 入门级 crypto 题

## 给定
- 密文字节流

## 前置条件
- 无现代密码结构

## 目标
恢复明文或密钥

## 算法步骤（来自 Crypton，算法层面）
1. Crypton 从分组密码起步，完全不含经典密码
2. 需外部资料：Cryptopals Set 1 / CryptoHack 入门章节

## 验证
明文可读

## 陷阱
- 本知识库起点偏高，新手题请另找资料

## 工具对齐（镜像真值）
pwn.xor 或 python3 已知明文异或。

交叉引用：advanced-math.md、classic-ciphers.md、exotic-crypto.md

