# BC-BLOCKSIZE-DETECT — 分组长度与模式探测

> kind=primitive · category=Block-Cipher · status=documented · source=ashutosh1206/Crypton@master

## 信号（题面可观测）
- 只有一个加密黑盒，不知块大小与模式
- 题目第一步要求识别加密方式

## 给定
- 加密 oracle

## 前置条件
- 可控制明文前缀

## 目标
确定 blocksize 与 ECB/CBC/CTR

## 算法步骤（来自 Crypton，算法层面）
1. 逐字节增加输入，密文长度首次跳变处即为 blocksize
2. 发送两个完全相同的连续块，密文对应两块相同则为 ECB
3. 结合长度变化与 IV 行为区分 CBC / CTR

## 验证
后续攻击能稳定复现

## 陷阱
- 有随机 IV 或前缀时需要先对齐到块边界
- 模式判断错误会导致后续所有步骤失败

## 工具对齐（镜像真值）
python3 + pycryptodome 加密不同长度明文探测块长。

交叉引用：modern-ciphers-2.md

相关模式：BC-ECB-BYTE-AT-A-TIME、BC-CBC-BIT-FLIPPING

原始文档：Block-Cipher/README.md
