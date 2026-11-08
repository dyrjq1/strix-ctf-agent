# RSA-UNPADDED-SIG-BLINDING — 无填充 RSA 签名乘性伪造（Blinding）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=example.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 签名直接对 hash 做 m^d mod n，无填充
- 可获取任意消息的签名

## 给定
- n
- e
- 签名 oracle

## 前置条件
- 无填充
- RSA 乘法同态

## 目标
伪造目标消息签名

## 算法步骤（来自 Crypton，算法层面）
1. 选 r，令 m' = m * r^e mod n
2. 请求 m' 的签名 s'
3. s = s' * r^-1 mod n 即为 m 的合法签名

## 验证
pow(s, e, n) == H(m)

## 陷阱
- 若 oracle 只肯签特定消息，可拆成多个已知签名的乘积
- 标准 PKCS#1 v1.5 填充可抵御此攻击

## 工具对齐（镜像真值）
python3 pow 盲化 + 手工拼 PKCS#1 结构；最终验签可用 pycryptodome。

交叉引用：rsa-attacks-2.md、exotic-crypto-2.md、exotic-crypto.md

相关模式：RSA-PKCS1-SIG-VERIFY

原始文档：Digital-Signatures/Unpadded-RSA-Digital-Signatures/README.md
