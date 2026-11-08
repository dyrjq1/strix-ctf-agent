# BC-ECB-BYTE-AT-A-TIME — ECB 逐字节解密（加密 oracle 附加秘密）

> kind=attack · category=Block-Cipher · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- 服务把 secret 拼接在用户输入之后一起加密并返回密文
- ECB 模式（相同明文块 → 相同密文块）

## 给定
- 加密 oracle

## 前置条件
- ECB
- 可控制输入前缀
- secret 固定

## 目标
逐字节恢复 secret

## 算法步骤（来自 Crypton，算法层面）
1. 先测出 blocksize
2. 构造输入使目标字节落在某块末尾，建立 256 个字节 → 密文块的字典
3. 比对目标块，逐字节推进；复杂度从 256^n 降到 256*n
4. 处理随机前缀时需填充对齐

## 验证
恢复出的 secret 重新加密能与目标块一致

## 陷阱
- 随机前缀/随机 IV 会破坏字典，必须先对齐
- PKCS#7 padding 会影响最后一字节判定

## 工具对齐（镜像真值）
python3 + pycryptodome；modern-ciphers.md 有实现。

交叉引用：modern-ciphers-2.md、modern-ciphers.md

相关模式：BC-CBC-BYTE-AT-A-TIME、BC-BLOCKSIZE-DETECT

原始文档：Block-Cipher/Attack-ECB-Byte-at-a-Time/README.md
