# DH-SMALL-SUBGROUP — Small Subgroup Confinement Attack

> kind=attack · category=DLP-EC-DH · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- DH 生成元 g 的阶含小因子（p-1 平滑）
- 可反复向对方发送自己的公钥并观察共享密钥/MAC

## 给定
- p
- g
- 对方公钥 A
- MAC 校验 oracle

## 前置条件
- 未验证公钥所属子群
- 可多次发起握手

## 目标
逐因子恢复对方私钥 x

## 算法步骤（来自 Crypton，算法层面）
1. 选一个小阶 r 的子群元素（阶 r | p-1）作为自己的公钥
2. 与对方握手得到共享密钥 k，枚举 k 的 r 种可能并用 MAC 验证
3. 得到 x mod r
4. 对多个小因子重复，最后 CRT 合并得到完整 x

## 验证
pow(g, x, p) == 对方公钥 A

## 陷阱
- 必须有办法验证猜测（如 MAC 校验），否则无法确认 x mod r
- p-1 不平滑时无法拆出足够多的小因子

## 工具对齐（镜像真值）
python3 分解小子群阶并枚举；dh-attacks.md。

交叉引用：advanced-math.md、ecc-attacks.md

相关模式：ECDH-INVALID-CURVE、DLP-POHLIG-HELLMAN

原始文档：Diffie-Hellman-Key-Exchange/Attack-Small-Subgroup-Confinement/README.md
