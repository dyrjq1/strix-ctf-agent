# AE-COMPOSITION — 认证加密组合方式判定

> kind=primitive · category=MAC-AE · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=encrypt-then-mac.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 题目同时给出密文和 tag，需要判断组合顺序
- 存在解密前/后校验差异可用于 padding oracle

## 给定
- 密文
- tag

## 前置条件
- 区分三种组合

## 目标
判断哪种组合最可能引入漏洞

## 算法步骤（来自 Crypton，算法层面）
1. Encrypt-and-MAC：tag 由明文独立生成，可能泄露明文信息
2. MAC-then-Encrypt：先认证明文再一起加密，解密后才校验，易产生 padding oracle
3. Encrypt-then-MAC：tag 由密文生成，先校验再解密，三者中最安全

## 验证
与服务端代码/协议描述一致

## 陷阱
- Crypton 明确结论：Encrypt-then-MAC 最安全
- 三种实现分别在 AE-with-MACs 下三个子目录

## 工具对齐（镜像真值）
pycryptodome 组合 Encrypt-then-MAC / MAC-then-Encrypt 对比示意。

交叉引用：modern-ciphers-3.md

相关模式：BC-CBC-PADDING-ORACLE

原始文档：Authenticated-Encryption/AE-with-MACs/Encrypt-then-MAC/README.md
