# RSA-LSB-ORACLE — RSA 最低位 oracle（二分恢复明文）

> kind=attack · category=RSA · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=encrypt.py:py3-fail; exploit.py:py3-fail; lsbitoracle.py:py3-ok — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 服务解密任意密文但只返回明文的最后一位（奇偶性）
- 允许选择密文查询
- n 在整个会话中保持不变

## 给定
- n
- e
- c
- LSB oracle

## 前置条件
- 无填充 RSA
- oracle 可持续查询约 log2(n) 次

## 目标
恢复任意密文对应明文

## 算法步骤（来自 Crypton，算法层面）
1. 利用 n 为奇数、2m mod n 的奇偶性随区间翻转
2. 发送 c*2^e mod n，按返回位缩小区间 [lo, hi]
3. 重复约 log2(n) 次直到区间收敛到唯一整数
4. 用分数分子/分母精确维护区间，避免浮点截断

## 验证
pow(m, e, n) == c

## 陷阱
- 用浮点中点会算错末字节：PR #9 正是修这个 bug（未合并）
- 会话重连导致 n 变化时需改用变体版
- 常见实现 bug：最后几个字节错误

## 工具对齐（镜像真值）
python3 二分交互（原 pari/gp 脚本一律改写为 python3 + gmpy2）；oracle 交互按题面用 requests/pwntools。

交叉引用：exotic-crypto-2.md、modern-ciphers-2.md、modern-ciphers-3.md

相关模式：RSA-LSB-ORACLE-VARIANT

原始文档：RSA-encryption/Attack-LSBit-Oracle/README.md
