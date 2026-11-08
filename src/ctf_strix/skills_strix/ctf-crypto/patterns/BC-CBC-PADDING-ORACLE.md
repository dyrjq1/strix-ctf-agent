# BC-CBC-PADDING-ORACLE — CBC Padding Oracle Attack

> kind=attack · category=Block-Cipher · status=thin · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- 服务对密文返回"填充正确/错误"两种可区分响应
- 报错信息、响应时间或 HTTP 状态码有差异

## 给定
- 加密密文（含 IV）
- padding oracle

## 前置条件
- CBC + PKCS#5/7 padding
- oracle 可重复查询

## 目标
不解密钥逐块解密（并可加密任意明文）

## 算法步骤（来自 Crypton，算法层面）
1. 从最后一块开始，暴力枚举中间字节使填充合法
2. 由合法响应推出 D(C_i) 中间值，再与前一密文块 XOR 得明文
3. 逐块向前推进；第一块需先求出 IV
4. 加密伪造时反向构造中间值

## 验证
解出的明文符合 PKCS#7 且语义可读

## 陷阱
- Crypton 该文档只有 545 字符，几乎没有推导，需外部资料
- 时间侧信道型 oracle 需要统计多次响应
- 第一块明文依赖 IV，配合 BC-CBC-IV-DETECT

## 工具对齐（镜像真值）
python3 + pycryptodome；本索引 §CBC Padding Oracle Attack 节有完整流程。

交叉引用：advanced-math.md、modern-ciphers-2.md、modern-ciphers-3.md

相关模式：BC-CBC-IV-DETECT

原始文档：Block-Cipher/Attack-CBC-Padding-Oracle/README.md
