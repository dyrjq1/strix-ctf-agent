# BC-CBC-BYTE-AT-A-TIME — CBC 逐字节解密

> kind=attack · category=Block-Cipher · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=exploit.py:py3-fail; secret.py:py3-ok — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 与 ECB 逐字节相同的 oracle 场景，但模式为 CBC；判别：同一明文块在不同位置得到不同密文块，每块依赖前一块密文（链接特性）

## 给定
- 加密 oracle

## 前置条件
- CBC
- 可控制输入
- secret 固定

## 目标
逐字节恢复 secret

## 算法步骤（来自 Crypton，算法层面）
1. 先探测块长，把注入输入截到块边界，使 secret 待测字节落在某块末字节
2. 逐字节试解：注入长度减一，用已解出前缀 + 候选字节 + 填充构成探测输入，取返回密文中对应块比对
3. CBC 下同明文块随前块密文变化——两次探测中待测块之前的明文完全相同（前块密文即固定），比对才有效；逐字节推进至 secret 末尾

## 验证
恢复出的 secret 重新加密，能复现同一密文块序列

## 陷阱
- Crypton 文档极短，仅给出外部博客链接，无独立推导
- 前一块密文参与 XOR，务必对齐

## 工具对齐（镜像真值）
攻击本体=对 oracle 的请求-比对循环（pwntools/套接字）；pycryptodome 只作本地 CBC 复算核对；攻击不操作 IV，IV 只影响首块——把待测块对齐到非首块即可。

交叉引用：modern-ciphers-2.md、modern-ciphers.md

相关模式：BC-ECB-BYTE-AT-A-TIME

原始文档：Block-Cipher/Attack-CBC-Byte-at-a-Time/README.md
