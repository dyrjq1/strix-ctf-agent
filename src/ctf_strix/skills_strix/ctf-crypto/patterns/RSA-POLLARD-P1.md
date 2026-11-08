# RSA-POLLARD-P1 — Pollard p-1 分解（p-1 平滑）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=exploit.py:py3-ok+requires-sage — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 题目说明素数由大量小因子乘积加 1 生成
- p-1 是 B-smooth
- 出现 handicraft_rsa 类题面

## 给定
- n

## 前置条件
- p-1（或 q-1）的所有素因子都小于界 B

## 目标
分解 n

## 算法步骤（来自 Crypton，算法层面）
1. 取 a = 2，对 B 以内所有素数幂 p^k 反复计算 a = pow(a, p^k, n)
2. 计算 g = gcd(a - 1, n)
3. 若 1 < g < n 则 g 是一个因子
4. g == 1 说明 B 太小，g == n 说明 B 太大需回退

## 验证
g > 1 and n % g == 0 and g != n

## 陷阱
- a 或 B 选择不当时会得到 g == n 的平凡结果
- 只适用于平滑数，普通 RSA 无效

## 工具对齐（镜像真值）
python3 + gmpy2.powmod 手写 p−1 光滑（B 界递增扫描）；RsaCtfTool 内含同类攻击可直接先试。

交叉引用：exotic-crypto-2.md、rsa-attacks-2.md、rsa-attacks.md

相关模式：RSA-FERMAT、DLP-POHLIG-HELLMAN

原始文档：RSA-encryption/Factorisation-Pollard's_p-1/README.md
