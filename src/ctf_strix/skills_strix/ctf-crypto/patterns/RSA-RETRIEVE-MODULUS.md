# RSA-RETRIEVE-MODULUS — 从加密 oracle 反推模数 n

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=extractmod.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 题目提供加密 oracle 但隐藏 n
- 有时连 e 也不给
- 第一步必须先把 n 求出来

## 给定
- 加密 oracle（可选 e）

## 前置条件
- 无填充 RSA
- 可自选明文并取回密文

## 目标
求出 n（进而做后续攻击）

## 算法步骤（来自 Crypton，算法层面）
1. e 已知：取多个 x_i，计算 gcd(x_i^e - c_i) 得到 n 的倍数
2. e 未知：对同一 x 的不同幂构造同余关系，用 gcd 组合消去
3. 对 gcd 结果去掉小因子得到 n

## 验证
pow(x, e, n) == 服务端返回的 c 对所有测试 x 成立

## 陷阱
- gcd 结果可能是 n 的倍数，需要剥离小因子
- e 未知方法同样适用于 e 已知情形

## 工具对齐（镜像真值）
python3 + gmpy2.gcd 对多组 (明文, 签名) 恢复 n。

交叉引用：rsa-attacks.md

相关模式：RSA-LSB-ORACLE

原始文档：RSA-encryption/Attack-Retrieve-Modulus/README.md
