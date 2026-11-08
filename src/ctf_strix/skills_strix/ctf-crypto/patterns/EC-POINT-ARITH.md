# EC-POINT-ARITH — 椭圆曲线点运算基础

> kind=primitive · category=DLP-EC-DH · status=documented · source=ashutosh1206/Crypton@master
>
> 代码警示：code_status=ellipticcurve.py:py3-fail; ellipticcurve.sage:sage-script; ellipticcurve.sage.py:py3-fail+requires-sage — 源码是 Python2/SageMath 时代产物，**只作算法参考，禁止直接执行**；转录公式使用前先复核。

## 信号（题面可观测）
- 题目给出自定义曲线参数 a, b, p
- 需要自己实现点运算

## 给定
- a
- b
- p

## 前置条件
- 有限域上的 Weierstrass 曲线

## 目标
实现加法/倍点/标量乘

## 算法步骤（来自 Crypton，算法层面）
1. 按公式计算点加与倍点的斜率
2. 用 double-and-add 实现标量乘
3. 注意无穷远点与模逆

## 验证
结合律测试：(P+Q)+R == P+(Q+R)

## 陷阱
- Montgomery Ladder 在 Crypton 中标记为 To be added，未实现
- 公式以 gif 图片存储，纯文本检索不到

## 工具对齐（镜像真值）
python3 点加/倍公式（ecc-attacks.md 有前置实现）。

交叉引用：ecc-attacks.md

相关模式：ECDLP-BSGS、ECDH-INVALID-CURVE

原始文档：Elliptic-Curves/README.md
