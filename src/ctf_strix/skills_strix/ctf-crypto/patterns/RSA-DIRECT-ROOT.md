# RSA-DIRECT-ROOT — RSA 小指数直接开根

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- e 很小（3/5/7）且密文 c 明显小于 n
- 题目说明无填充 textbook RSA
- m^e 未超过模数，取模没有发生

## 给定
- n
- e
- c

## 前置条件
- e 小
- m^e < n
- 无随机填充

## 目标
直接恢复明文 m

## 算法步骤（来自 Crypton，算法层面）
1. 检测 c 是否为完全 e 次幂：对 c 开 e 次方（整数）
2. 若整数根成立，m 即为明文
3. 若不成立说明发生了模约简，改用其他攻击

## 验证
pow(root, e) == c（注意若 m^e >= n 则该等式不成立）

## 陷阱
- 必须用整数开方，浮点 pow(c, 1/e) 在大数上会失真
- 若只是 e 小而 m 不小，应转 Hastad 广播或 Coppersmith

## 工具对齐（镜像真值）
gmpy2.iroot(c, e) 整数开根（禁浮点 pow(c, 1/e)，大数必失真）；纯 python3，无外部工具依赖。

交叉引用：rsa-attacks-2.md、rsa-attacks.md

相关模式：RSA-HASTAD、RSA-COPPERSMITH-STEREOTYPED

备注：原理在 RSA-encryption/README.md 的 Padding and Padding Schemes 小节，无独立文档。

原始文档：RSA-encryption/README.md
