# ctf-crypto — Attack Pattern Router signal tables

> Moved verbatim from the index under the 8KB gate. Protocol and warnings live in the index; this file holds the per-family signal tables. After a row matches, read the card at `patterns/<ID>.md`.

### RSA (18)

| 题面信号 | 模式卡 |
|---|---|
| e 很小（3/5/7）且密文 c 明显小于 n；题目说明无填充 textbook RSA | [RSA-DIRECT-ROOT](patterns/RSA-DIRECT-ROOT.md) — RSA 小指数直接开根 |
| 题目提示 p 与 q 很接近 / 生成时用了 nextprime；n 能被快速平方差分解 | [RSA-FERMAT](patterns/RSA-FERMAT.md) — Fermat 分解（p、q 接近） |
| 题目说明素数由大量小因子乘积加 1 生成；p-1 是 B-smooth | [RSA-POLLARD-P1](patterns/RSA-POLLARD-P1.md) — Pollard p-1 分解（p-1 平滑） |
| 给了两个或更多模数 n1, n2, ...；题目提示素数生成器有故障 / 复用了素数 | [RSA-COMMON-PRIME](patterns/RSA-COMMON-PRIME.md) — 公共素因子攻击（多个 n 共享 p） |
| 同一明文用同一个 n、两个不同 e 加密得到 c1、c2；gcd(e1, e2) == 1 | [RSA-COMMON-MODULUS](patterns/RSA-COMMON-MODULUS.md) — 共模攻击（同 n 不同 e） |
| e 与 n 同量级（异常大，如 1024 位以上）；题目提示 d 很小 / 私钥生成有问题 | [RSA-WIENER](patterns/RSA-WIENER.md) — Wiener 攻击（小私钥指数 d） |
| 标准 Wiener 收敛项验不出来，但 e 仍然异常大；题目说明 d 比 N^0.25 大几个比特 | [RSA-WIENER-VARIANT](patterns/RSA-WIENER-VARIANT.md) — Wiener 变体（d 略超 N^0.25） |
| 同一明文用相同小 e 发给 k 个不同模数；k >= e | [RSA-HASTAD](patterns/RSA-HASTAD.md) — Hastad 广播攻击（同小 e、多个 n） |
| 每个接收者的明文是 M + a_i*常数 之类已知线性变换；小 e 广播但直接开根失败 | [RSA-HASTAD-PADDED](patterns/RSA-HASTAD-PADDED.md) — Hastad 广播 + 线性填充（Coppersmith 扩展） |
| 同一 (n,e) 下两条消息满足已知线性关系 M2 = f(M1)；题目给出 c1、c2 和关系式 | [RSA-FRANKLIN-REITER](patterns/RSA-FRANKLIN-REITER.md) — Franklin-Reiter 相关消息攻击 |
| 明文的绝大部分已知，只剩少量未知字节（如 flag 前缀）；c = (known + x)^e mod n，x 很小 | [RSA-COPPERSMITH-STEREOTYPED](patterns/RSA-COPPERSMITH-STEREOTYPED.md) — Coppersmith 定型消息攻击（已知明文高位） |
| 题目泄露了 p 的高位比特（通常需 >= 一半位长）；给了 p 的部分比特或近似值 | [RSA-COPPERSMITH-HIGHBITS](patterns/RSA-COPPERSMITH-HIGHBITS.md) — Coppersmith 已知 p 高位分解 n |
| 服务解密任意密文但只返回明文的最后一位（奇偶性）；允许选择密文查询 | [RSA-LSB-ORACLE](patterns/RSA-LSB-ORACLE.md) — RSA 最低位 oracle（二分恢复明文） |
| oracle 每次连接会更换 n；需要在断线后继续恢复剩余比特 | [RSA-LSB-ORACLE-VARIANT](patterns/RSA-LSB-ORACLE-VARIANT.md) — LSB oracle 变体（逐位、可跨会话续跑） |
| 题目提供加密 oracle 但隐藏 n；有时连 e 也不给 | [RSA-RETRIEVE-MODULUS](patterns/RSA-RETRIEVE-MODULUS.md) — 从加密 oracle 反推模数 n |
| PKCS#1 v1.5 签名验证不检查 0xFF 填充长度；e = 3 | [RSA-BLEICHENBACHER-E3](patterns/RSA-BLEICHENBACHER-E3.md) — e=3 Bleichenbacher 签名伪造 |
| 签名直接对 hash 做 m^d mod n，无填充；可获取任意消息的签名 | [RSA-UNPADDED-SIG-BLINDING](patterns/RSA-UNPADDED-SIG-BLINDING.md) — 无填充 RSA 签名乘性伪造（Blinding） |
| 题目给出签名和公钥，需要判断验证器是否严格；出现 DigestInfo / ASN.1 前缀 | [RSA-PKCS1-SIG-VERIFY](patterns/RSA-PKCS1-SIG-VERIFY.md) — PKCS#1 v1.5 签名填充结构与校验点 |

### 分组密码 (7)

| 题面信号 | 模式卡 |
|---|---|
| 只有一个加密黑盒，不知块大小与模式；题目第一步要求识别加密方式 | [BC-BLOCKSIZE-DETECT](patterns/BC-BLOCKSIZE-DETECT.md) — 分组长度与模式探测 |
| 服务把 secret 拼接在用户输入之后一起加密并返回密文；ECB 模式（相同明文块 → 相同密文块） | [BC-ECB-BYTE-AT-A-TIME](patterns/BC-ECB-BYTE-AT-A-TIME.md) — ECB 逐字节解密（加密 oracle 附加秘密） |
| 与 ECB 逐字节相同的加密 oracle（secret 拼在用户输入后）；同一明文块在不同位置得到不同密文块，每块依赖前一块密文（链接特性） | [BC-CBC-BYTE-AT-A-TIME](patterns/BC-CBC-BYTE-AT-A-TIME.md) — CBC 逐字节解密（加密 oracle 附加秘密） |
| 解密 oracle 可用但 IV 不公开；padding oracle 攻击解不出第一块 | [BC-CBC-IV-DETECT](patterns/BC-CBC-IV-DETECT.md) — CBC 未知 IV 恢复 |
| 服务端把用户输入拼进明文、过滤敏感字符后加密成 cookie；解密时直接信任 cookie 内容 | [BC-CBC-BIT-FLIPPING](patterns/BC-CBC-BIT-FLIPPING.md) — CBC 比特翻转（篡改 cookie 提权） |
| 服务端把 = 替换成 ? 之类字符过滤后再用 CTR 加密；CTR/流密码模式，密文与明文逐字节 XOR 对应 | [BC-CTR-BIT-FLIPPING](patterns/BC-CTR-BIT-FLIPPING.md) — CTR 比特翻转（流密码式篡改） |
| 服务对密文返回"填充正确/错误"两种可区分响应；报错信息、响应时间或 HTTP 状态码有差异 | [BC-CBC-PADDING-ORACLE](patterns/BC-CBC-PADDING-ORACLE.md) — CBC Padding Oracle Attack |

### MAC / 认证加密 (6)

| 题面信号 | 模式卡 |
|---|---|
| CBC-MAC 用于变长消息且 IV 固定；服务允许为任意消息生成 tag | [MAC-CBCMAC-FORGERY](patterns/MAC-CBCMAC-FORGERY.md) — CBC-MAC 变长消息伪造 |
| 已知 MAC(M1)，需要 M1／／M2 的合法 tag；服务拒绝直接对 M1／／M2 求 tag | [MAC-CBCMAC-LENGTH-EXT](patterns/MAC-CBCMAC-LENGTH-EXT.md) — CBC-MAC 长度扩展攻击 |
| 协议没有时间戳/nonce/序号；可截获合法 (消息, tag) 对 | [MAC-REPLAY](patterns/MAC-REPLAY.md) — MAC 重放攻击 |
| 同一 nonce/key 加密了两条不同消息，且都给出 tag；题目强调 nonce 重复或计数器回绕 | [AE-GCM-NONCE-REUSE](patterns/AE-GCM-NONCE-REUSE.md) — AES-GCM Forbidden Attack（nonce 重用） |
| 题目涉及 GCM tag 计算、关联数据 AAD；需要理解 H 与 J0 的作用 | [AE-GCM-INTERNALS](patterns/AE-GCM-INTERNALS.md) — AES-GCM / GHASH 结构 |
| 题目同时给出密文和 tag，需要判断组合顺序；存在解密前/后校验差异可用于 padding oracle | [AE-COMPOSITION](patterns/AE-COMPOSITION.md) — 认证加密组合方式判定 |

### 离散对数 / 椭圆曲线 / DH (10)

| 题面信号 | 模式卡 |
|---|---|
| 给定 g, h = g^x mod p，群阶很小；需要求 x | [DLP-BRUTE](patterns/DLP-BRUTE.md) — 离散对数暴力搜索 |
| 群阶为素数或不易分解，但规模中等；内存充足 | [DLP-BSGS](patterns/DLP-BSGS.md) — Baby-Step Giant-Step 求 DLP |
| 群阶为素数；内存受限，不能用 BSGS | [DLP-POLLARD-RHO](patterns/DLP-POLLARD-RHO.md) — Pollard's Rho 求 DLP（素数阶） |
| 群阶 n 可分解为小素数幂；p-1 是 smooth number | [DLP-POHLIG-HELLMAN](patterns/DLP-POHLIG-HELLMAN.md) — Pohlig-Hellman（平滑阶群） |
| 给定椭圆曲线基点 P 与 Q = x*P；基点阶为中等规模素数 | [ECDLP-BSGS](patterns/ECDLP-BSGS.md) — ECDLP 的 Baby-Step Giant-Step |
| 基点阶为素数时需要唯一解；内存受限 | [ECDLP-POLLARD-RHO](patterns/ECDLP-POLLARD-RHO.md) — ECDLP 的 Pollard's Rho |
| 题目给出自定义曲线参数 a, b, p；需要自己实现点运算 | [EC-POINT-ARITH](patterns/EC-POINT-ARITH.md) — 椭圆曲线点运算基础 |
| DH 生成元 g 的阶含小因子（p-1 平滑）；可反复向对方发送自己的公钥并观察共享密钥/MAC | [DH-SMALL-SUBGROUP](patterns/DH-SMALL-SUBGROUP.md) — Small Subgroup Confinement Attack |
| ECDH 服务端不校验收到的点是否落在约定曲线上；可多次提交自选点并观察结果 | [ECDH-INVALID-CURVE](patterns/ECDH-INVALID-CURVE.md) — Invalid Curve Point Attack |
| 基于椭圆曲线的挑战-响应身份认证；验证器只检查单个响应值 | [ID-EPHEMERAL-FORGERY](patterns/ID-EPHEMERAL-FORGERY.md) — 临时密钥身份认证的伪造与作弊检测 |

### 签名 / ElGamal (3)

| 题面信号 | 模式卡 |
|---|---|
| 两条不同消息的签名具有相同的 r；题目暗示签名随机数生成器有问题 | [ECDSA-K-REUSE](patterns/ECDSA-K-REUSE.md) — ECDSA nonce(k) 重用恢复私钥 |
| 题目给出 (p, g, y) 与签名 (r, s)；需要验证 pow(g,h,p) == pow(r,s,p)*pow(y,r,p) mod p | [ELGAMAL-SIG](patterns/ELGAMAL-SIG.md) — ElGamal 签名方案结构 |
| 密文是 (c1, c2) 一对；题目给出群 p、生成元 g、公钥 | [ELGAMAL-ENC](patterns/ELGAMAL-ENC.md) — ElGamal 加密与不安全生成元 |

### GAP 声明缺口 (8)

| 题面信号 | 模式卡 |
|---|---|
| Wiener 失败但 d 仍偏小；e 接近 n 且 d < N^0.292 | **[G]** [GAP-BONEH-DURFEE](patterns/GAP-BONEH-DURFEE.md) — Boneh-Durfee 攻击（d < N^0.292） |
| RSA 解密服务返回"填充是否合法"；题目是 CCA 型 oracle | **[G]** [GAP-PKCS1-PADDING-ORACLE](patterns/GAP-PKCS1-PADDING-ORACLE.md) — PKCS#1 v1.5 加密填充 oracle |
| 题目基于可预测的伪随机数生成器；给出若干连续输出要求预测下一个 | **[G]** [GAP-PRNG](patterns/GAP-PRNG.md) — PRNG 预测（LCG / Mersenne Twister / LFSR） |
| 题目出现格、LWE、高维向量、背包；Coppersmith 之外的 small_roots 场景 | **[G]** [GAP-LATTICE](patterns/GAP-LATTICE.md) — 格密码与 LLL（LWE / NTRU / 背包） |
| MAC = hash(secret ／／ message)，secret 长度已知；需要为追加内容生成合法 MAC | **[G]** [GAP-HASH-LENGTH-EXT](patterns/GAP-HASH-LENGTH-EXT.md) — Merkle-Damgård 哈希长度扩展 |
| 多条签名，nonce 的高位/低位已知或固定；r 值各不相同但存在偏置 | **[G]** [GAP-ECDSA-NONCE-BIAS](patterns/GAP-ECDSA-NONCE-BIAS.md) — ECDSA nonce 部分泄露 / 偏置（格攻击） |
| 同一消息得到一条正确签名和一条错误签名；题目提示签名时发生了一次计算错误 | **[G]** [GAP-CRT-FAULT](patterns/GAP-CRT-FAULT.md) — RSA-CRT 故障攻击（Bellcore） |
| 题目是字节流、频率分析、重复密钥 XOR；入门级 crypto 题 | **[G]** [GAP-CLASSIC-XOR](patterns/GAP-CLASSIC-XOR.md) — 经典/XOR/编码类密码 |
