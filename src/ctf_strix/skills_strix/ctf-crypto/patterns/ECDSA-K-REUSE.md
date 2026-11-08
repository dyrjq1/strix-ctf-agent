# ECDSA-K-REUSE — ECDSA nonce(k) 重用恢复私钥

> kind=attack · category=Signature-ElGamal · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- 两条不同消息的签名具有相同的 r
- 题目暗示签名随机数生成器有问题

## 给定
- (r, s1, h1)
- (r, s2, h2)
- 曲线阶 n

## 前置条件
- 两条签名用了同一个 k

## 目标
恢复 k 与私钥 dA，进而伪造任意签名

## 算法步骤（来自 Crypton，算法层面）
1. 由 s1 - s2 = k^-1 (h1 - h2) 得 k = (h1-h2)/(s1-s2) mod n
2. 由 s = k^-1 (h + r*dA) 得 dA = (s*k - h)/r mod n
3. 用 dA 对任意消息签名

## 验证
dA*G == 公钥 Q

## 陷阱
- 所有运算 mod n，且 r 必须可逆
- 仅有部分 nonce 比特泄露时需用格攻击（Crypton 未覆盖）

## 工具对齐（镜像真值）
python3 + gmpy2.invert 联立两签名恢复 k。

交叉引用：advanced-math.md、ecc-attacks.md、lattice-and-lwe.md

相关模式：GAP-ECDSA-NONCE-BIAS

原始文档：Digital-Signatures/Elliptic-Curve-DSA/Attack-k-reuse/README.md
