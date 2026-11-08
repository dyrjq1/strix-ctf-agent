# GAP-PKCS1-PADDING-ORACLE — [缺口] PKCS#1 v1.5 加密填充 oracle

> kind=gap · category=GAP · status=gap · source=ashutosh1206/Crypton@master
>
> ⚠️ **缺口条目**：Crypton 未实现/未文档化此攻击。本卡给出镜像内可行的替代路径与既有部分覆盖；命中即应考虑向用户声明缺口，不要硬套近似攻击。

## 信号（题面可观测）
- RSA 解密服务返回"填充是否合法"
- 题目是 CCA 型 oracle

## 给定
- c
- padding oracle

## 前置条件
- PKCS#1 v1.5 加密填充

## 目标
恢复明文

## 算法步骤（来自 Crypton，算法层面）
1. Crypton TODO 中列为待实现
2. 需外部资料：Bleichenbacher 1998 / ROBOT 攻击

## 验证
 pow(m,e,n) == c

## 陷阱
- 与 CBC padding oracle 是完全不同的算法

## 工具对齐（镜像真值）
无现成工具（无 sage / ROBOT 脚本）；本索引 §Bleichenbacher RSA Padding Oracle (ROBOT) 节有手写思路，oracle 交互 python3 现场实现。

交叉引用：modern-ciphers.md、rsa-attacks-2.md、rsa-attacks.md

相关模式：RSA-LSB-ORACLE
