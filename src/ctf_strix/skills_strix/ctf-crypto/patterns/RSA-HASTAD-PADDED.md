# RSA-HASTAD-PADDED — Hastad 广播 + 线性填充（Coppersmith 扩展）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=hastad_unpadded.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 每个接收者的明文是 M + a_i*常数 之类已知线性变换
- 小 e 广播但直接开根失败

## 给定
- e
- k >= e 组 (n_i, c_i)
- 每个线性填充函数

## 前置条件
- k >= e
- 填充为已知线性/仿射函数

## 目标
恢复原始 M

## 算法步骤（来自 Crypton，算法层面）
1. 为每个接收者构造 g_i(x) = (a_i*x + b_i)^e - c_i mod n_i
2. CRT 合并成单个模 N=prod(n_i) 的多项式
3. 化为首一多项式后求 small_roots
4. 回代验证得到 M

## 验证
对每个 i，pow(f_i(M), e, n_i) == c_i

## 陷阱
- 原法用 SageMath small_roots；镜像无 sage，替代路径见「工具对齐」
- 仍要求 k >= e 且未知根足够小

## 工具对齐（镜像真值）
镜像无 fpylll/SageMath：advanced-math.md 的 Howgrave-Graham 流程其 LLL 步依赖 fpylll，仅作伪码参考；镜像路径=python3 现写 LLL + Howgrave-Graham，CRT 合并后求小根，写不出则声明缺口。

交叉引用：rsa-attacks-2.md、rsa-attacks.md

相关模式：RSA-HASTAD、RSA-COPPERSMITH-STEREOTYPED

原始文档：RSA-encryption/Attack-Hastad-Broadcast/README.md
