# BC-CBC-BIT-FLIPPING — CBC 比特翻转（篡改 cookie 提权）

> kind=attack · category=Block-Cipher · status=thin · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- 服务端把用户输入拼进明文、过滤敏感字符后加密成 cookie
- 解密时直接信任 cookie 内容
- CBC 模式

## 给定
- 加密 cookie
- 解密/登录服务

## 前置条件
- CBC
- 可拿到密文并回传

## 目标
让解密后明文变成 admin=true

## 算法步骤（来自 Crypton，算法层面）
1. 定位目标字符在前一块密文中的下标 n
2. C[n-1] = C[n-1] XOR 当前字符 XOR 期望字符
3. 回传修改后的 cookie；代价是前一块明文被打乱，需让其落在无用字段

## 验证
服务端解密 cookie 后得到目标字符串（如 admin=true）

## 陷阱
- 修改 C[i-1] 会同时打乱第 i-1 块明文，需让该块落在无意义字段
- 与 CTR 版机制不同，不能只改目标字节而不管前一块

## 工具对齐（镜像真值）
python3 XOR（pwn.xor 可用）；modern-ciphers.md。

交叉引用：ecc-attacks.md、exotic-crypto-2.md、rsa-attacks-2.md

相关模式：BC-CTR-BIT-FLIPPING、BC-CBC-IV-DETECT

原始文档：Block-Cipher/Attack-CBC-Bit-Flipping/README.md
