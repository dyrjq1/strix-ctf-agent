# RSA-COPPERSMITH-HIGHBITS — Coppersmith 已知 p 高位分解 n

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=exploit.py:py3-fail+requires-sage — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 题目泄露了 p 的高位比特（通常需 >= 一半位长）
- 给了 p 的部分比特或近似值

## 给定
- n
- p 的高位

## 前置条件
- 已知 p 的约一半以上比特

## 目标
恢复完整 p 并分解 n

## 算法步骤（来自 Crypton，算法层面）
1. 设 p = p_high + x，构造 f(x) = p_high + x mod N
2. 用 beta=0.5、epsilon 参数的 small_roots 求小根 x
3. 得到 p 后 q = n // p

## 验证
p * q == n 且 isprime(p)

## 陷阱
- 已知高位不足约一半比特时 small_roots 求不出
- Crypton 的 exploit.py 含语法错误，须用 SageMath 重写

## 工具对齐（镜像真值）
同 advanced-math.md 流程：已知 p 高位构造单变量多项式再 LLL 求小根。

交叉引用：advanced-math.md、lattice-and-lwe.md、post-quantum.md

相关模式：RSA-COPPERSMITH-STEREOTYPED、GAP-LATTICE

原始文档：RSA-encryption/Attack-Coppersmith/README.md
