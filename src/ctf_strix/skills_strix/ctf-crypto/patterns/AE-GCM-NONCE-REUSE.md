# AE-GCM-NONCE-REUSE — AES-GCM Forbidden Attack（nonce 重用）

> kind=attack · category=MAC-AE · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- 同一 nonce/key 加密了两条不同消息，且都给出 tag
- 题目强调 nonce 重复或计数器回绕

## 给定
- 两组 (ciphertext, tag, nonce)
- associated data 长度

## 前置条件
- 同一 H = E_K(0)
- nonce 重用

## 目标
恢复认证子密钥 H 并伪造任意 tag

## 算法步骤（来自 Crypton，算法层面）
1. 两条消息同 nonce → 两条 tag 对应同一个多项式在 H 处的取值
2. 两式相减得到以 H 为未知数的多项式，其常数项为零
3. 在 GF(2^128) 上求根得到 H（可能有多个候选，用第三条消息筛）
4. 得到 H 后即可对任意 C/AAD 计算合法 tag

## 验证
用求得的 H 对第三条同 nonce 消息算出的 tag 与服务端一致

## 陷阱
- GF(2^128) 上求根可能得到多个候选 H，必须用额外消息筛选
- Crypton 的 AES-GCM 实现本身有已知 bug（issue #5 未修）

## 工具对齐（镜像真值）
python3 双密文 XOR 恢复明文/伪造密文；pycryptodome AES-GCM 做加解密验证。

交叉引用：advanced-math.md、modern-ciphers-2.md、modern-ciphers-4.md

相关模式：AE-GCM-INTERNALS

原始文档：Authenticated-Encryption/AES-GCM/Attack-Forbidden/README.md
