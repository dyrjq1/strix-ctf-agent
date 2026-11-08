# RSA-FRANKLIN-REITER — Franklin-Reiter 相关消息攻击

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=exploit.sage:sage-script — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 同一 (n,e) 下两条消息满足已知线性关系 M2 = f(M1)
- 题目给出 c1、c2 和关系式

## 给定
- n
- e
- c1
- c2
- f(x)

## 前置条件
- 无填充
- f 为已知线性多项式
- 同一模数

## 目标
恢复 M1、M2

## 算法步骤（来自 Crypton，算法层面）
1. 构造 g1(x) = f(x)^e - c2, g2(x) = x^e - c1
2. 在 Z_n[x] 上求多项式 GCD
3. 若 GCD 为一次式 x - M1，直接读出明文

## 验证
pow(M1, e, n) == c1 and pow(f(M1), e, n) == c2

## 陷阱
- 需要 SageMath 或 sympy 的多项式 GCD 支持
- f 为高次时 GCD 计算代价高

## 工具对齐（镜像真值）
python3 + sympy.Poly 做模 n 多项式 GCD；rsa-attacks.md 有 sage-free 实现（sympy 路线）。

交叉引用：rsa-attacks.md

相关模式：RSA-COPPERSMITH-STEREOTYPED

原始文档：RSA-encryption/Attack-Franklin-Reiter/README.md
