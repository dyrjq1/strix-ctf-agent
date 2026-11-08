# MAC-CBCMAC-LENGTH-EXT — CBC-MAC 长度扩展攻击

> kind=attack · category=MAC-AE · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=CBC-Length-Extension.py:py3-fail; key.py:py3-ok — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 已知 MAC(M1)，需要 M1||M2 的合法 tag
- 服务拒绝直接对 M1||M2 求 tag

## 给定
- MAC(M1)
- M2
- MAC oracle（可选）

## 前置条件
- CBC-MAC
- IV 已知或为空

## 目标
在不知密钥下得到 MAC(M1||M2)

## 算法步骤（来自 Crypton，算法层面）
1. IV 为空：把 MAC(M1) XOR M2 作为输入送给 oracle，返回即 MAC(M1||M2)
2. IV 非空：把 MAC(M1) XOR M2 XOR IV 相关量按文档推导处理
3. 分 IV 为空 / 非空两种情况分别实现

## 验证
服务端接受 (M1||M2, tag)

## 陷阱
- IV 未知时需先恢复
- 不要与哈希长度扩展（Merkle-Damgård）混淆，Crypton 未覆盖后者

## 工具对齐（镜像真值）
python3 手写 CBC-MAC 长度扩展（新首块 XOR 旧 MAC 作 IV）。

交叉引用：modern-ciphers.md

相关模式：MAC-CBCMAC-FORGERY、GAP-HASH-LENGTH-EXT

原始文档：Message-Authentication-Code/Attack-Length-Extension-CBC-MAC/README.md
