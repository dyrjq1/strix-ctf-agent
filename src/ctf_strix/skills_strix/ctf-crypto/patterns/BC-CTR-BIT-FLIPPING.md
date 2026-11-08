# BC-CTR-BIT-FLIPPING — CTR 比特翻转（流密码式篡改）

> kind=attack · category=Block-Cipher · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- 服务端把 = 替换成 ? 之类字符过滤后再用 CTR 加密
- CTR/流密码模式，密文与明文逐字节 XOR 对应

## 给定
- 加密 cookie
- 登录服务

## 前置条件
- CTR 或任意流密码
- 已知目标位置明文

## 目标
把密文对应字节改成期望明文

## 算法步骤（来自 Crypton，算法层面）
1. 定位目标字节在密文中的下标 n
2. C[n] = C[n] XOR 期望字符 XOR 当前字符
3. 回传修改后的密文即可登录

## 验证
服务端解密后得到期望字符串（如 admin=true）

## 陷阱
- 与 CBC 不同，CTR 不需要修改前一块密文
- Crypton README 主表里把 CTR 描述误写成 CBC，注意区分

## 工具对齐（镜像真值）
python3 XOR；CTR 无填充，密文位直接翻对应明文位。

交叉引用：ecc-attacks.md、exotic-crypto-2.md、rsa-attacks-2.md

相关模式：BC-CBC-BIT-FLIPPING

原始文档：Block-Cipher/Attack-CTR-Bit-Flipping/README.md
