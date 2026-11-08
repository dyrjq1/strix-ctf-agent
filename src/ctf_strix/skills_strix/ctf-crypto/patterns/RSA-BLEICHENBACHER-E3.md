# RSA-BLEICHENBACHER-E3 — e=3 Bleichenbacher 签名伪造

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- PKCS#1 v1.5 签名验证不检查 0xFF 填充长度
- e = 3
- 验证器只比对 ASN.1 + hash 前缀

## 给定
- n
- e=3
- 签名验证器

## 前置条件
- 验证器跳过填充字节检查
- 小 e

## 目标
在无私钥下伪造合法签名

## 算法步骤（来自 Crypton，算法层面）
1. 构造形如 00 01 FF..FF 00 ASN.1 HASH garbage 的目标块
2. 把填充区当作可自由填充的字节，使整个块成为某个数的完全立方
3. 对目标块开三次方得到伪造签名 s
4. s^3 mod n 被宽松验证器接受

## 验证
宽松验证器接受 (m, s)

## 陷阱
- Crypton 该文档只有外链，没有推导，需读 Filippo Valsorda / Hal Finney 的原始资料
- 仅对实现有缺陷的验证器有效，标准 PKCS#1 v1.5 校验会拒绝

## 工具对齐（镜像真值）
python3 枚举填充前缀 + gmpy2.iroot 逐个试整数根。

交叉引用：modern-ciphers.md、rsa-attacks-2.md、rsa-attacks.md

相关模式：RSA-PKCS1-SIG-VERIFY、RSA-UNPADDED-SIG-BLINDING

原始文档：Digital-Signatures/Attack-e=3-Bleichenbacher/README.md
