# RSA-COMMON-PRIME — 公共素因子攻击（多个 n 共享 p）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- 给了两个或更多模数 n1, n2, ...
- 题目提示素数生成器有故障 / 复用了素数
- 同一批 key 中出现重复因子

## 给定
- n1
- n2
- e

## 前置条件
- gcd(ni, nj) > 1

## 目标
分解所有相关模数

## 算法步骤（来自 Crypton，算法层面）
1. 对全部模数两两计算 p = gcd(ni, nj)
2. p > 1 则 q_i = n_i / p
3. d_i = inverse(e, (p-1)(q_i-1))，分别解密

## 验证
p * q_i == n_i 对所有 i 成立，且 pow(pow(m,e,n_i), d_i, n_i) == m

## 陷阱
- gcd 必须是对大整数精确计算
- 若 gcd 结果等于 n 说明两个模数完全相同，属于平凡情况

## 工具对齐（镜像真值）
python3 手写（在 gcd(p−1, q−1) 值域搜公共素数）+ sympy.factorint 辅助小因子；镜像无现成 CLI。

交叉引用：rsa-attacks-2.md

相关模式：RSA-HASTAD、RSA-FERMAT

原始文档：RSA-encryption/Attack-Common-Prime/README.md
