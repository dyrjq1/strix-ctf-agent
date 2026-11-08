# RSA-COPPERSMITH-STEREOTYPED — Coppersmith 定型消息攻击（已知明文高位）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=exploit.py:py3-fail+requires-sage — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 明文的绝大部分已知，只剩少量未知字节（如 flag 前缀）
- c = (known + x)^e mod n，x 很小

## 给定
- n
- e
- c
- 已知明文模板

## 前置条件
- 未知量 x < N^(1/e)
- 单变量首一多项式

## 目标
求小根 x，恢复完整明文

## 算法步骤（来自 Crypton，算法层面）
1. 构造首一多项式 f(x) = (m + x)^e - c mod N
2. 用 LLL / Howgrave-Graham 求 small_roots(X, beta, epsilon)
3. 验证候选根

## 验证
pow(m + x, e, n) == c

## 陷阱
- Crypton 的 exploit.py 含 `def N-factorize` 语法错误，且是 Sage 专用语法，纯 Python 无法运行
- 镜像无 SageMath：走「工具对齐」节的现写路径，不要试图装 sage

## 工具对齐（镜像真值）
镜像无 fpylll/SageMath：advanced-math.md 的 Coppersmith 流程其 LLL 步依赖 fpylll，仅作伪码参考；镜像路径=python3 现写 LLL + Howgrave-Graham（sympy 只承担最后的多项式求根），写不出则声明缺口。

交叉引用：advanced-math.md、lattice-and-lwe.md、post-quantum.md

相关模式：RSA-FRANKLIN-REITER、RSA-COPPERSMITH-HIGHBITS、GAP-BONEH-DURFEE

原始文档：RSA-encryption/Attack-Coppersmith/README.md
