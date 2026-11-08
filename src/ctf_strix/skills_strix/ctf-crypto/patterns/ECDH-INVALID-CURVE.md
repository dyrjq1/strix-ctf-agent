# ECDH-INVALID-CURVE — Invalid Curve Point Attack

> kind=attack · category=DLP-EC-DH · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- ECDH 服务端不校验收到的点是否落在约定曲线上
- 可多次提交自选点并观察结果

## 给定
- 曲线 a, b, p
- 对方公钥 Q
- 握手 oracle

## 前置条件
- 缺少 on-curve 校验
- a 固定，可构造不同 b 的曲线

## 目标
用小阶曲线逐段恢复私钥

## 算法步骤（来自 Crypton，算法层面）
1. 固定 a，枚举 b 使得新曲线 E_i 的阶含小素因子 n_i
2. 在 E_i 上找小阶点（Tonelli-Shanks 求平方根）
3. 用该点与对方做握手，由共享密钥反推 x mod n_i
4. 多个 n_i 用 CRT 拼回完整 x

## 验证
x*P == Q

## 陷阱
- Crypton 特别说明：与 Small Subgroup Confinement 的适用条件完全不同
- 需要点验证缺失这一实现缺陷，标准库通常已防护

## 工具对齐（镜像真值）
python3 无效曲线点算术 + BSGS；ecc-attacks.md。

交叉引用：ecc-attacks.md

相关模式：DH-SMALL-SUBGROUP、EC-POINT-ARITH

原始文档：Diffie-Hellman-Key-Exchange/Attack-Invalid-Curve-Point/README.md
