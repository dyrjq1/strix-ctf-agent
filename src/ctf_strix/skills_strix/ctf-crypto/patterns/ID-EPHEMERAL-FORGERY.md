# ID-EPHEMERAL-FORGERY — 临时密钥身份认证的伪造与作弊检测

> kind=attack · category=DLP-EC-DH · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- 基于椭圆曲线的挑战-响应身份认证
- 验证器只检查单个响应值

## 给定
- 曲线基点 P
- 公钥 Q = x*P
- 验证器

## 前置条件
- 挑战可预测或可重放

## 目标
伪造 Prover 身份 / 检测作弊

## 算法步骤（来自 Crypton，算法层面）
1. 分析平凡算法：直接发送 x 会泄露私钥
2. 临时密钥方案中构造 s、r 满足验证等式
3. 验证器通过额外检查确认 Prover 同时知道 s 与 r

## 验证
验证器接受响应且未泄露 x

## 陷阱
- Crypton 此部分偏理论，配套 challenge 是自建服务
- 与 Schnorr 签名安全性分析相关但文档未展开

## 工具对齐（镜像真值）
python3 EC 点算术构造中间人密钥交换；ecc-attacks.md。

交叉引用：dh-attacks.md、exotic-crypto-2.md

相关模式：EC-POINT-ARITH

原始文档：Identification/Ephemeral-Key-Auth/README.md
