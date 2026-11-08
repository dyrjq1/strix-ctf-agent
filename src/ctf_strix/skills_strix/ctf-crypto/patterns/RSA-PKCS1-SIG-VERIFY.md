# RSA-PKCS1-SIG-VERIFY — PKCS#1 v1.5 签名填充结构与校验点

> kind=primitive · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=example.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 题目给出签名和公钥，需要判断验证器是否严格
- 出现 DigestInfo / ASN.1 前缀

## 给定
- 签名
- 公钥

## 前置条件
- 理解 00 01 FF..FF 00 || DigestInfo 结构

## 目标
定位可绕过的校验环节

## 算法步骤（来自 Crypton，算法层面）
1. 检查 00 01 前缀
2. 检查 FF 填充长度与内容是否被真正校验
3. 检查 ASN.1 + hash 之后是否允许尾随垃圾字节

## 验证
逐项比对标准 EMSA-PKCS1-v1_5 编码

## 陷阱
- Crypton 文档明确指出漏洞在于验证函数不检查 FF 填充
- 宽松实现直接导致 e=3 伪造

## 工具对齐（镜像真值）
pycryptodome 的 Crypto.Signature.pkcs1_15（镜像内置）。

交叉引用：modern-ciphers.md、rsa-attacks-2.md、rsa-attacks.md

相关模式：RSA-BLEICHENBACHER-E3

原始文档：Digital-Signatures/PKCS#1-v1.5-Padded-RSA-Digital-Signature/README.md
