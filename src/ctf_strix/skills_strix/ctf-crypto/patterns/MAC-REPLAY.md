# MAC-REPLAY — MAC 重放攻击

> kind=attack · category=MAC-AE · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- 协议没有时间戳/nonce/序号
- 可截获合法 (消息, tag) 对

## 给定
- 合法 (M, T)

## 前置条件
- 验证端不检查新鲜性

## 目标
重复提交已认证消息

## 算法步骤（来自 Crypton，算法层面）
1. 原样重放截获的消息与 tag
2. 检查是否存在防重放机制

## 验证
服务端再次接受该消息

## 陷阱
- 属于协议层缺陷，不是密码算法缺陷
- Crypton 仅在 MAC 安全分析小节列举，未展开

## 工具对齐（镜像真值）
非计算型攻击：识别重放条件后用 python3 脚本验证；无专用工具。

交叉引用：exotic-crypto.md、modern-ciphers.md、prng.md


原始文档：Message-Authentication-Code/README.md
