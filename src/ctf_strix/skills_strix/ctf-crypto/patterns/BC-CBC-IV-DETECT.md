# BC-CBC-IV-DETECT — CBC 未知 IV 恢复

> kind=attack · category=Block-Cipher · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=example.py:py3-fail — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 解密 oracle 可用但 IV 不公开
- padding oracle 攻击解不出第一块

## 给定
- 解密 oracle

## 前置条件
- CBC
- 可提交任意密文并读取明文

## 目标
求出 IV

## 算法步骤（来自 Crypton，算法层面）
1. 取密文第一块 c1
2. 提交 c1 + 00*blocksize + c1
3. 解密后取第一块明文 p1 与第三块明文 p3
4. IV = p1 XOR p3

## 验证
用求得的 IV 解密第一块得到预期明文

## 陷阱
- 需要至少 3 个密文块
- 是 padding oracle 攻击第一块明文的前置步骤

## 工具对齐（镜像真值）
python3 + pycryptodome：改首块密文翻转已知明文，验证 IV 即首段密文。

交叉引用：modern-ciphers-2.md、modern-ciphers-3.md、modern-ciphers-4.md

相关模式：BC-CBC-PADDING-ORACLE

原始文档：Block-Cipher/CBC-IV-Detection/README.md
