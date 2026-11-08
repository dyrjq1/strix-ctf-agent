# GAP-HASH-LENGTH-EXT — [缺口] Merkle-Damgård 哈希长度扩展

> kind=gap · category=GAP · status=gap · source=ashutosh1206/Crypton@master
>
> ⚠️ **缺口条目**：Crypton 未实现/未文档化此攻击。本卡给出镜像内可行的替代路径与既有部分覆盖；命中即应考虑向用户声明缺口，不要硬套近似攻击。

## 信号（题面可观测）
- MAC = hash(secret || message)，secret 长度已知
- 需要为追加内容生成合法 MAC

## 给定
- 原始消息与 MAC
- secret 长度

## 前置条件
- MD 结构的哈希

## 目标
伪造更长消息的 MAC

## 算法步骤（来自 Crypton，算法层面）
1. Crypton 的 MAC 安全分析小节提到该攻击名但未展开，仓库无实现
2. 需外部工具 hashpump 或自行实现 padding 续算

## 验证
服务端接受伪造 MAC

## 陷阱
- 与 CBC-MAC 长度扩展机制不同，不要混用

## 工具对齐（镜像真值）
镜像无 hashpumpy；本索引 §Hash Length Extension Attack 节有思路，python3 现写 MD 压缩函数续算（约 60 行）。

交叉引用：modern-ciphers-2.md、modern-ciphers-3.md、modern-ciphers.md

相关模式：MAC-CBCMAC-LENGTH-EXT
