# MAC-CBCMAC-FORGERY — CBC-MAC 变长消息伪造

> kind=attack · category=MAC-AE · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- CBC-MAC 用于变长消息且 IV 固定
- 服务允许为任意消息生成 tag

## 给定
- MAC oracle

## 前置条件
- 固定 IV
- 消息长度可变
- 无长度编码

## 目标
构造两条不同消息共享同一 tag

## 算法步骤（来自 Crypton，算法层面）
1. 取单块消息 i1，向 oracle 拿 MAC(i1)
2. 构造 i2 = MAC(i1) XOR 目标明文块
3. 构造 i3 = MAC(i2) XOR MAC(i1) XOR i1
4. 提交 s2 = i2 || i3，其 tag 与 s1 相同

## 验证
MAC(s1) == MAC(s2) 且 s1 != s2

## 陷阱
- 仅对固定 IV、允许变长消息的 CBC-MAC 有效
- 加入长度前缀或改用 CMAC 后即失效

## 工具对齐（镜像真值）
python3 手写 CBC-MAC（pycryptodome AES 原语做 glue 拼接）。

交叉引用：modern-ciphers.md

相关模式：MAC-CBCMAC-LENGTH-EXT

原始文档：Message-Authentication-Code/CBC-MAC-Forgery/README.md
