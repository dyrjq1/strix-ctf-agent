"""Fixed tag -> method card table, plus the web playbook skeleton.

Why this layer exists is recorded in docs/11-实验台账.md (2026-11-12): the
failures were mostly wrong-direction, not wrong-payload.  The routing table
says which *index* to load; a card says which check to run first and with
which of our own tools.

Two hard properties, both covered by tests:

* **Zero injection surface.**  Card text is a literal in this module.  Platform
  tags are lowered and used only for set intersection -- they are never
  concatenated into the rendered text.  No tag, challenge name, target or
  description reaches the prompt through this path.
* **Bounded size.**  At most :data:`MAX_CARDS` cards, never more than
  :data:`MAX_CHARS` characters playbook included.  A technique list paid on
  every call is the token tax :mod:`ctf_strix.routing` already warns about.

Every name inside backticks is a registered tool in :mod:`ctf_strix.catalogue`;
``tests/test_method_cards.py`` scans the whole table so a typo cannot ship.

A card is also dropped when this run did not install a tool it names: telling
the model to call ``ai_quick_scan`` on a run without it costs a turn and
teaches it to distrust the block.  ``available=None`` disables that filter
(the card table itself is still checked by the scan above, which is what
catches a typo in a card nobody happens to hit).
"""

from __future__ import annotations

import os
import re
from collections.abc import Collection
from dataclasses import dataclass
from typing import Iterable

#: Cards injected per run.  Measured tables hit three to five; eight is slack.
MAX_CARDS = 8

#: Hard ceiling for the whole block (playbook + cards + header), in characters.
MAX_CHARS = 1200

#: Ceiling for the playbook alone; the rest of the budget belongs to cards.
PLAYBOOK_MAX_CHARS = 620

#: Kinds that get the web playbook.  ``agent`` is reserved: agentic-AI tasks
#: currently arrive as ``web`` through ``agent._challenge_kind``.
WEB_KINDS: frozenset[str] = frozenset({"web", "agentic"})

HEADER = "[Method cards] tag 命中：下面只给看哪里和先后顺序，工具名照用。"

PLAYBOOK = (
    "[Web playbook] 五阶段，每阶段有出口判据，不许跳级。\n"
    "0 取材：读题面、首页、JS 与提示，一行写下技术栈、入口、flag 形态。\n"
    "  附件用 `exec_command` 落盘再读，不整包打印。\n"
    "1 指纹：`http_probe` 打根路径与一条随机路径；全路径同体=死站，记录后停止。\n"
    "  版本用 `web_cve_lookup` 对一次；没版本就按框架结构打。\n"
    "2 枚举：`route_map` 一次列真实路由，`method_sweep` 打最好的两条。\n"
    "  备份与编码变体交 `path_variants`；从命中里选一条最像 flag 出口的，交给 3。\n"
    "3 深挖：先写证伪条件，把 2 选中的面推到利用成功——读到行/文件/命令回显才算完。\n"
    "  一次只改一个变量；新名字加不出新攻击类就换机制，换类不换名字。\n"
    "4 收口：flag 在响应体/头/上传文件里；落盘再 grep，不整包打印。\n"
    "  拿到即原样提交；无逐字输出依据就写未验证。"
)


@dataclass(frozen=True)
class Card:
    """One method card: a stable id, the tags that select it, its fixed text.

    ``cid`` 是给"第五轮自选"那条链路用的稳定标识（模型按 id 点卡）。默认取
    第一个键，这样新增卡不必手工编号；同一张表里出现重复首键时必须显式给 id。
    """

    cid: str
    keys: frozenset[str]
    text: str

    @property
    def title(self) -> str:
        """菜单里显示的一行标题：正文第一句，截到 24 字。"""
        head = self.text.split("：", 1)[0].split("。", 1)[0]
        return head[:24]


def _card(keys: str, text: str, cid: str = "") -> Card:
    parts = frozenset(k.strip() for k in keys.split(",") if k.strip())
    return Card(cid or (sorted(parts)[0] if parts else ""), parts, text)


#: Table order is priority: AI cards first (narrower), then technique cards,
#: then stack cards last -- a truncated run drops stacks, not mechanisms.
CARDS: tuple[Card, ...] = (
    _card(
        "agentic_ai,agent_goal_hijack,inter_agent,rogue_agent,excessive_agency",
        "Agent 题：决策点在工具调用而非页面。`ai_quick_scan` 先扫，`ai_fingerprint` 认框架，再把目标改写成它能执行的动作。",
    ),
    _card(
        "prompt_injection,indirect_prompt_injection,memory_poisoning,data_binding",
        "提示注入：先列输入通道（消息/文件/网页/工具回显），每通道用 `http_probe` 或 `exec_command` 投一个标记串，看输出是否复述。",
    ),
    _card(
        "tool_misuse,mcp,untrusted_plugins,plugin_poisoning",
        "工具滥用：先拿工具名与参数（问模型或看报错），找接受 URL/路径/命令的参数，再用 `http_probe` 把越权目标塞进去。",
    ),
    _card(
        "rag,llm_proxy",
        "RAG/模型服务：`http_probe` 看 /v1/models、/api/tags；检索层按 collection/tenant 参数试越权，再考虑投毒文档。",
    ),
    _card(
        "content_moderation,auto_approval,fail_open,integrity_theatre",
        "护栏/审核：记一次被拒的原话，用 `http_probe` 只改一个维度（语言/编码/角色/分步）再试；同维度两次被拒就换维度。",
    ),
    _card(
        "sandbox_escape,unexpected_code_execution,bash",
        "沙箱逃逸：先用 `exec_command` 确认执行原语（能跑什么、禁了什么），再逐个突破限制；一次只改一个限制条件。",
    ),
    _card(
        "sqli,injection,nosql_injection",
        "注入：先定注入点类型（数字/字符/括号），`http_probe` 单参数看报错、布尔、时间三态；两次同回显就换机制。",
    ),
    _card(
        "reflected_xss,stored_xss,dom_xss,csp",
        "XSS：先判回显上下文（HTML/属性/JS/URL），一次一种编码；无回显就查 CSP 与存储点，批量 payload 用 `exec_command` 循环。",
    ),
    _card(
        "ssrf,server_side_request_forgery,dns_rebinding",
        "SSRF：参数可能是 URL。`http_probe` 分别指向回环与云元数据地址；被拦就用 `path_variants` 造编码变体。",
    ),
    _card(
        "lfi,path_traversal,path_normalization",
        "LFI/穿越：`path_variants` 生成 ../ 与编码变体，一次一组；命中标志是固定文件头（/etc/passwd 首行），不是 200。",
    ),
    _card(
        "file_upload,jsp_upload,webshell",
        "上传：先定校验维度（扩展名/MIME/魔术字节/内容），一次只改一个；multipart 用 `exec_command` 的 python 发。",
    ),
    _card(
        "rce,command_injection,reverse_shell",
        "命令注入：先证明拼接（; | $() 的差异），再定通道（回显/时间/OOB）；用 `exec_command` 做 sleep 5 与 sleep 0 的基线差。",
    ),
    _card(
        "ssti,template_injection,jinja2,ognl_injection,groovy",
        "SSTI：`http_probe` 打 {7*7} 与 {{7*7}}，出 49 再判引擎（Jinja/Twig/OGNL），按引擎试读文件。",
    ),
    _card(
        "deserialization,unsafe_deserialization,phar_deserialization,xstream",
        "反序列化：先认格式（PHP O:/Java AC ED/pickle）；`web_cve_lookup` 查组件版本链，版本对得上再搓 gadget。",
    ),
    _card(
        "jwt,jwt_none,jwks,signature_bypass",
        "JWT：`exec_command` 解 header 看 alg；alg=none 与弱密钥各试一次；分清“验签失败”与“解析失败”。",
    ),
    _card(
        "predictable_code,authentication_failures,otp,mfa,two_factor,account_merge,"
        "2fa_bypass,account_recovery,password_reset",
        "认证流程：`route_map` 列全登录/OTP/找回/绑定端点并画状态机；先测顺序再测值——同码重放、"
        "跳步、乱序提交、A 的对象带进 B 的会话；每步记状态码与长度差，合并/绑定类看哪侧属性被覆盖。",
        cid="auth.flow",
    ),
    _card(
        "software_supply_chain,supply_chain,malicious_install,dependency_confusion,typosquatting",
        "供应链：安装/构建/部署动作本身就是攻击面。先 `load_skill` 供应链方向读前三个探针，"
        "再定位安装源与命名规则，造同名或近似名包并触发安装，从 setup.py/postinstall 取执行。",
    ),
    _card(
        "idor,broken_access_control,mass_assignment,2fa_bypass,account_merge",
        "越权：两个账号互换同名资源 id，看是否 200 且内容不同；`traffic_list` 回看已发请求里的 id/role 字段。两个账号放两个具名会话（session 参数分别写 alice 与 bob），否则后登录的会把前一个的 cookie 覆盖掉。",
        cid="authz.idor",
    ),
    _card(
        "weak_password,default_credentials,brute_force,authentication_bypass,password_reset",
        "弱口令/认证：先试默认口令一组，再试登录处 SQLi 绕过；`http_probe` 一组一发，控制频率。登录成功后会话按 host 自动保留，直接打下一个路径——别自己抄 cookie，也别重发登录请求。",
    ),
    _card(
        "debug_endpoint,information_disclosure,secret_exposure,secret_leak,sourcemap",
        "信息泄漏：先 `http_probe` /robots.txt、/sitemap.xml、/.git/HEAD、/.DS_Store；命中后 `exec_command` 落盘再 grep。",
    ),
    _card(
        "graphql,api,apq",
        "GraphQL/API：`http_probe` POST {__typename} 探 introspection；开了就 dump schema，没开就按字段名猜。",
    ),
    _card(
        "xxe,ldap,jndi_injection",
        "XXE/JNDI：先 `http_probe` 确认解析器（Content-Type 与报错）；外部实体指本地文件看回显，不通就走 DNS 外带。",
    ),
    _card(
        "prototype_pollution,open_redirect,csrf,jsonp,origin_trust",
        "信任边界：找能吃 URL/回调/来源的参数；`http_probe` 换 Host、Origin、Referer 各一次，看信任判断在哪层。",
    ),
    _card(
        "cache_deception,cache,concurrency,business_logic",
        "缓存/并发：先确认单次是否幂等；用 `exec_command` 并发 N 份看有无超额成功；缓存键看是否忽略某个头或参数。",
    ),
    _card(
        "php,laravel,wordpress,drupal",
        "PHP 栈：优先 include、上传、反序列化、弱比较；`path_variants` 试 .bak、~、.swp 备份。",
    ),
    _card(
        "flask,python-flask,python,jinja2",
        "Flask/Python 栈：优先 SSTI、debug console、穿越；用 `http_probe` 看到 traceback 就是 debug 开着。",
    ),
    _card(
        "nodejs,node-express,express,nextjs,react_server_components,vite,vue3,sveltekit,nuxt3,node",
        "Node/前端栈：优先原型链污染、SSRF、SSR 模板注入；`http_probe` 发 __proto__ 探针，看后续响应是否被改。",
    ),
    _card(
        "java,spring_framework,apache_struts2,apache_tomcat,apache_solr,jenkins,tomcat,spring4shell",
        "Java 栈：先 `http_probe` /actuator/env 与 /actuator/heapdump；`web_cve_lookup` 查版本，再考虑 SpEL/OGNL。",
    ),
    _card(
        "log4j,log4shell,cve_2021_44228",
        "Log4Shell：先确认有无回连通道，再用 ${jndi:ldap://x} 打一个 header；`http_probe` 发一次看回显差异。",
    ),
)


def tags_of(task: dict | None) -> list[str]:
    """Read only the tag fields of a task; names and descriptions stay out."""
    if not isinstance(task, dict):
        return []
    out: list[str] = []
    challenge = task.get("challenge")
    if isinstance(challenge, dict):
        out.extend(str(t) for t in (challenge.get("tags") or []))
    out.extend(str(t) for t in (task.get("tags") or []))
    return [t for t in out if t]


def _keys(tags: Iterable[str] | None) -> set[str]:
    return {t.strip().lower() for t in (tags or ()) if isinstance(t, str) and t.strip()}


#: A tool name is a lowercase identifier inside backticks.  The table-wide scan
#: in ``tests/test_method_cards.py`` guarantees every such span is a catalogue
#: entry, so this cannot pick up prose or a shell flag (``--flag`` starts with
#: a dash) by accident.
_TOOL_REF = re.compile(r"`([a-z][a-z0-9_]*)`")


def tools_named(text: str) -> frozenset[str]:
    """Every tool a card asks the model to call, in backtick order.

    Args:
        text: card body (or any prose that names tools in backticks).

    Returns:
        The distinct names; empty when the text names none.
    """
    return frozenset(_TOOL_REF.findall(text))


def select(
    tags: Iterable[str] | None,
    kind: str | None,
    limit: int = MAX_CARDS,
    available: Collection[str] | None = None,
) -> list[Card]:
    """Cards whose key set intersects ``tags``, in table (priority) order.

    Args:
        tags: challenge tags; only used for the key intersection.
        kind: challenge kind; anything without a web surface gets nothing.
        limit: maximum number of cards.
        available: tool names registered in this run.  A card naming a tool
            outside this set is skipped -- see the module docstring.  ``None``
            disables the filter (the caller cannot see the registry).

    Returns:
        Matching cards; empty for a kind with no web surface, no tags, or no
        card whose tools are all installed.
    """
    if kind not in WEB_KINDS:
        return []
    wanted = _keys(tags)
    if not wanted:
        return []
    known = None if available is None else frozenset(available)
    out: list[Card] = []
    for card in CARDS:
        if not (card.keys & wanted) or card in out:
            continue
        if known is not None and not tools_named(card.text) <= known:
            continue
        out.append(card)
        if len(out) >= limit:
            break
    return out


def _disabled_keys() -> frozenset[str]:
    """Card keys the ``CTF_CARDS_OFF`` env switch suppresses.

    Ablation-only: a card's A/B arms must differ by exactly that card, and the
    batch harness runs both arms from one working tree (ledger §4.235).  Unset,
    blank or unknown keys return an empty set, so the default is byte-identical
    to the pre-switch behaviour.  Keys are compared case-insensitively, the same
    way :func:`select` treats incoming tags.
    """
    raw = os.environ.get("CTF_CARDS_OFF", "")
    return frozenset(k.strip().lower() for k in raw.split(",") if k.strip())


def render(
    tags: Iterable[str] | None,
    kind: str | None = None,
    available: Collection[str] | None = None,
) -> str:
    """Render the block for ``user_instructions``; empty string when nothing hits.

    Cards are appended in priority order and the loop stops before the block
    would exceed :data:`MAX_CHARS`, so the lowest-priority cards are the ones
    dropped.  A run with no matching card injects nothing at all.

    Cards whose key set intersects ``CTF_CARDS_OFF`` are dropped before the
    budget loop, exactly as if they were not in the table.  ``select`` stays
    pure so the table-level tests can keep calling it without env noise.
    """
    cards = select(tags, kind, available=available)
    disabled = _disabled_keys()
    if disabled:
        cards = [card for card in cards if not (card.keys & disabled)]
    if not cards:
        return ""
    lines = [PLAYBOOK]
    used = len(HEADER) + 1 + len(PLAYBOOK)
    for card in cards:
        line = "- " + card.text
        cost = 1 + len(line)
        if used + cost > MAX_CHARS:
            break
        lines.append(line)
        used += cost
    return "\n".join([HEADER, *lines])


# ---------------------------------------------------------------- 非 web 方向卡
#
# 2026-11-19 从参考工程（D:\ycjctf\ctfy_project\src\ctfy_agent\method_cards.py 的
# DOMAIN_CARDS / CATEGORY_FALLBACK）移植：结构与"先看什么、按什么顺序"的判据
# 照抄，**工具名全部改成本仓库 catalogue 里的**（它点名 pwnkit/rsatool/aesblock/
# z3solve 等我们没有的工具，直接抄会让 tests/test_method_cards.py 的
# "backticked name must be registered" 断言失败，模型也会调不存在的工具）。
#
# 键取自平台真实 tag 词表：今天的 pwn 题带 heap、reverse 题带 reverse，都能命中。

DOMAIN_CARDS: tuple[Card, ...] = (
    _card(
        "reverse,stripped,per_team_artifact,per-team-artifact",
        "REV 定型四步：`hexpeek` 看魔数判型（ELF/PE/pyc/脚本）→ `elfpeek` view=info 看架构/PIE/入口 → "
        "view=symbols 找校验函数（被 strip 就靠 view=strings 的提示串与常量推理）→ view=disasm 只反汇编"
        "可疑函数那一段。别整段反汇编，步数会烧光；.pyc/PyInstaller 先用 `exec_command` 跑反编译再读。",
        cid="rev.triage",
    ),
    _card(
        "xor,rc4,rc4_xor,bytecode",
        "REV 算法复现：先用已知输入（全 0、全 1、题面样例）在本地把加密函数跑出来，再对密文求逆；"
        "XOR/查表/位运算优先用 `exec_command` 写 python 复现并对拍。爆破空间 <1e6 直接穷举；更大就找"
        "前缀匹配、CRC、长度、字符集约束收窄，不要盲爆。",
        cid="rev.alg",
    ),
    _card(
        "bof,stack,elf",
        "PWN 栈溢出四步：`elfpeek` view=info 看 PIE/NX/canary → view=symbols/strings 找 gets/read/"
        "system/win → `exec_command` 生成 cyclic 模式串、`tcp` 发超长触发崩溃 → `elffind` 反查精确偏移。"
        "有附件 libc 就照它的符号算 system 与 /bin/sh；payload 落盘后用 `tcp` 发，别手搓转义串。"
        "崩溃看不懂就在 `exec_command` 里跑 gdb -batch 看 rip 与栈。",
        cid="pwn.stack",
    ),
    _card(
        "format_string,rop,seccomp",
        "PWN 进阶：格式化串先用 `tcp_batch` 批量试 %1$p..%20$p 一次收敛、定位自己的输入位置，再谈 %n 写；"
        "没有 win 函数走 ROP，`elfpeek` view=gadgets filter=rdi|rsi|rdx|syscall；堆题先看 malloc/free "
        "顺序与 tcache 是否 double-free，别急着一次打通；远程先泄漏 libc 基址再算偏移。",
        cid="pwn.adv",
    ),
    _card(
        "heap,asan,sanitizer,use_after_free,uaf,arbitrary_read",
        "PWN 泄漏链四步（ASan/记录管理器类）：① 先用已打通的任意读写读『结构固定字段』——self/label/"
        "blob.data 里通常就有 heap 与 PIE 指针；② 用 `elfpeek` view=info/symbols 加附件 libc 的符号偏移"
        "把 PIE 指针→PIE base、GOT 项→libc base；③ 每次读 8 字节都打印 hex 与**实际长度**并断言长度=8"
        "（短读先修读取长度，别假设成功）；④ 拿到 base 后再构造 openat/read/write 或 ret2libc。"
        "每步落一个可重跑脚本 + 一条断言，失败先看是哪一步。",
        cid="pwn.leak",
    ),
    _card(
        "rsa,small_e,wiener,common_modulus",
        "CRYPTO RSA 先自动试：`exec_command` 写 python（pycryptodome/gmpy2）依次试 小指数开方 / wiener / "
        "共模 / fermat（p、q 相邻）。有「明文结构」线索就走格攻击（Coppersmith 小根、LLL）；都不中就找 n 的"
        "分解线索（题面提示、共享因子、p=q），拿到 d 后用 `hexpeek` 拼明文再 `decode_blob` 剥编码。",
        cid="crypto.rsa",
    ),
    _card(
        "aes,ecb,oracle,cbc",
        "CRYPTO 分组密码：先判模式——16 字节对齐后出现相同块 = ECB；ECB 打块剪切/字节翻转移位取目标块；"
        "CBC 打 IV 与前一密文块的位翻转；padding oracle 用 `tcp_batch` 一次批量试末字节（≤200/轮）。"
        "密钥已知就用 `exec_command` 本地算（ecb/cbc/ctr），别手搓分组填充。",
        cid="crypto.block",
    ),
    _card(
        "zip,archive,forensics",
        "MISC 归档/取证：`unpack_archive` 按魔数解包（zip 加密先判 ZipCrypto 还是 AES，别硬跑）；"
        "常见套路是伪加密（改通用标志位）、注释/文件名/额外字段藏值、CRC 与明文碰撞；取证先 `hexpeek` "
        "看头与尾部附加数据，再 `decode_blob` 剥编码链，不要整文件打印。",
        cid="misc.archive",
    ),
    _card(
        "udp,connectivity,pcap,stego,image_encoding",
        "MISC 通道/隐写：先判可达（不可达=环境问题，立刻收口）；UDP/自定义协议没有专用工具——用 "
        "`exec_command` 落一个 python socket 脚本再跑；隐写/图片先 `hexpeek` 看尾部与 ZIP/PNG 文本块，"
        "再 `decode_blob` 逐层剥。",
        cid="misc.channel",
    ),
)

#: 按 category 的兜底决策表：tag 一个都不中时用（题型词太粗是常态）。
#: 文案照参考工程的 CATEGORY_FALLBACK，工具名换成本仓库的。
CATEGORY_FALLBACK: dict[str, Card] = {
    "pwn": _card(
        "pwn",
        "PWN 决策表（按保护与可用原语选路线，先本地验证再打远端）：① 有后门/win 且栈可执行 → ret2text，"
        "`elffind` 取函数偏移；② 无后门但能泄露 → ret2libc：`elfpeek` view=symbols 定位 GOT/plt → libc base"
        " → system(/bin/sh)；③ 静态链接无 libc → ret2syscall 或 SROP；④ 64 位无 pop rdi → ret2csu；"
        "⑤ 有格式化串 → `tcp_batch` 批量试 %p 定位再 %n；⑥ 堆题 → malloc/free 顺序、tcache double-free/UAF。"
        "纪律：`exec_command` 里跑 gdb 本地确认偏移，本地不通不打远端；payload 落盘后 `tcp` 发。",
        cid="fallback.pwn",
    ),
    "rev": _card(
        "rev",
        "REV 决策表：① 先判型（ELF/PE/.pyc/APK/脚本/压缩包）；② `elfpeek` 的 strings+symbols 定位校验函数与"
        "硬编码比较值，只反汇编该函数（不要全文读）；③ 能本地执行就差分验证：不同输入比对分支/输出，把"
        "「输入→比较→输出」钉死；④ 校验是方程/约束 → 用 `exec_command` 跑 z3 解；⑤ 常见算法手工复现"
        "（异或/RC4/TEA/迷宫/矩阵）；⑥ 被 strip → 用字符串与常量交叉定位。",
        cid="fallback.rev",
    ),
    "crypto": _card(
        "crypto",
        "CRYPTO 决策表：① 先判题型（RSA/分组/流密码/哈希/格/协议）；② RSA 先试 小指数/wiener/共模/fermat，"
        "再考虑 Coppersmith 与 LLL；③ 分组先判模式（ECB 重复块、CBC 位翻转、CTR 复用流）；④ 流密码查 "
        "nonce/密钥复用；⑤ 一切「给定方程/多项式」优先喂 z3，不要手推。`exec_command` 里跑 python 对拍。",
        cid="fallback.crypto",
    ),
    "misc": _card(
        "misc",
        "MISC 决策表：① 先 `file_triage` 判家族（归档/图片/流量/硬件描述/编码）；② 归档与取证走 "
        "`unpack_archive`+`hexpeek`+`decode_blob`；③ 硬件/逻辑题先照题面重建状态机或真值表，再用 "
        "`exec_command` 复算并与给定输出对拍；④ 一段时间没进展就回到题面找「输入-输出样例」，"
        "有样例优先做差分而不是继续猜。",
        cid="fallback.misc",
    ),
}

#: file / tcp 的短流程（web 那份见 :data:`PLAYBOOK`）。粒度与 web 一致：
#: 只讲先后与出口判据，不点具体技术。
FILE_PLAYBOOK = (
    "[File playbook] 五阶段，每阶段有出口判据。\n"
    "0 取证：`file_triage` 判家族与下一步，一行写下文件类型、保护、flag 形态。\n"
    "1 拆包：`unpack_archive` 递归到最内层，记下每层的格式与是否加密。\n"
    "2 读：`hexpeek` / `elfpeek` 定点读，不整包打印；被 strip 只看 strings 与符号。\n"
    "3 复现：`exec_command` 写 python 脚本把「输入→输出」跑通，用题面样例对拍。\n"
    "4 收口：拿到即原样提交；无逐字依据就写未验证。"
)

TCP_PLAYBOOK = (
    "[TCP playbook] 五阶段，每阶段有出口判据。\n"
    "0 连接：`tcp` 拿 banner，记下协议与交互格式。\n"
    "1 静态：`elfpeek` view=info/symbols 看保护、后门、输入函数。\n"
    "2 触发：`tcp` 发超长或畸形输入看崩溃/回显，`tcp_batch` 批量试参数。\n"
    "3 定位：`elffind` 反查偏移，本地复现后再打远端。\n"
    "4 收口：payload 落盘再发，flag 原样提交。"
)

#: kind → 起手 playbook。
PLAYBOOKS: dict[str, str] = {"web": PLAYBOOK, "file": FILE_PLAYBOOK, "tcp": TCP_PLAYBOOK}


def playbook(kind: str | None) -> str:
    """该 kind 的起手流程文本；未知 kind 返回空串。"""
    return PLAYBOOKS.get(str(kind or ""), "")


#: 平台类别词 → 兜底表的键。平台写 ``reverse``，表里写 ``rev``。
CATEGORY_ALIASES: dict[str, str] = {
    "web": "web",
    "pwn": "pwn",
    "crypto": "crypto",
    "rev": "rev",
    "reverse": "rev",
    "reversing": "rev",
    "misc": "misc",
    "forensics": "misc",
    "forensic": "misc",
}

#: 题面没有类别线索时按接入面兜底：远程二进制服务就是 pwn；
#: 纯附件题先按 misc 的"取证→拆包"走，第一张卡就让它自己再定型。
_KIND_DEFAULT_CATEGORY: dict[str, str] = {"tcp": "pwn", "file": "misc"}


def category_of(
    tags: Iterable[str] | None,
    kind: str | None = None,
    declared: str | None = None,
) -> str:
    """题目大类：平台显式字段优先，其次 tags 里的类别词，最后按 kind 兜底。

    Args:
        tags: 题目 tags（平台词表，已小写化比较）。
        kind: ``agent._challenge_kind`` 的结果。
        declared: 平台详情接口的 ``category`` 字段（可缺）。

    Returns:
        ``pwn`` / ``rev`` / ``crypto`` / ``misc`` / ``web`` 之一；都没线索时
        返回空串（此时非 web 题不进兜底卡）。
    """
    first = str(declared or "").strip().lower()
    if first in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[first]
    for tag in sorted(_keys(tags)):
        if tag in CATEGORY_ALIASES:
            return CATEGORY_ALIASES[tag]
    return _KIND_DEFAULT_CATEGORY.get(str(kind or ""), "")


def _usable(cards: Iterable[Card], available: Collection[str] | None) -> list[Card]:
    """按本 run 的真实工具面与 ``CTF_CARDS_OFF`` 过滤（同一套规则，一处实现）。"""
    known = None if available is None else frozenset(available)
    disabled = _disabled_keys()
    return [
        card
        for card in cards
        if not (card.keys & disabled)
        and (known is None or tools_named(card.text) <= known)
    ]


def pool(
    kind: str | None,
    category: str | None,
    tags: Iterable[str] | None,
    available: Collection[str] | None = None,
) -> list[Card]:
    """该题的候选卡池（第五轮菜单用）：web 走技术键，非 web 走方向键→category 兜底。

    web 的 tag 一个都不中时（平台给的是题型词，这是常态）返回**整张 web 表**：
    菜单只有 id + 一行标题，让模型按已观测的证据自己挑，这正是这个池存在的
    理由。返回空列表表示这题确实没有卡。

    Args:
        kind: 题型。
        category: :func:`category_of` 的结果。
        tags: 题目 tags，只做集合求交，原文不进提示。
        available: 本进程实际注册的工具名；卡点名了未注册工具就剔卡。
    """
    k = str(kind or "")
    if k in WEB_KINDS:
        hits = _usable(select(tags, k), available)
        return hits or _usable(CARDS, available)
    if k not in {"file", "tcp"}:
        return []
    wanted = _keys(tags)
    hit = _usable([card for card in DOMAIN_CARDS if card.keys & wanted], available)
    if hit:
        return hit
    fallback = CATEGORY_FALLBACK.get(str(category or "").strip().lower())
    return _usable([fallback], available) if fallback is not None else []


def start_cards(
    kind: str | None,
    category: str | None,
    tags: Iterable[str] | None,
    *,
    limit: int = 3,
    available: Collection[str] | None = None,
) -> list[Card]:
    """起手就发的那几张：tag 命中的卡；非 web 没命中时发一张 category 兜底卡。

    web 没命中时**不发整表的前三张**——表序是优先级（AI 卡在前），把 AI 打法
    塞给一道普通 web 题是 2026-11-19 复核里点名的反模式。没命中就只给
    playbook，具体打法交给第五轮的自选。
    """
    cap = max(int(limit), 0)
    k = str(kind or "")
    if k in WEB_KINDS:
        return _usable(select(tags, k), available)[:cap]
    if k not in {"file", "tcp"}:
        return []
    wanted = _keys(tags)
    hit = _usable([card for card in DOMAIN_CARDS if card.keys & wanted], available)
    if hit:
        return hit[:cap]
    fallback = CATEGORY_FALLBACK.get(str(category or "").strip().lower())
    if fallback is None:
        return []
    usable = _usable([fallback], available)
    return usable[:cap]


def render_start(
    kind: str | None,
    category: str | None,
    tags: Iterable[str] | None,
    *,
    limit: int = 3,
    available: Collection[str] | None = None,
) -> str:
    """起手注入块：playbook（只看 kind）+ 至多 ``limit`` 张起手卡。

    与旧的 :func:`render` 的差别：playbook 不再因为卡片未命中而整块不发——
    2026-11-19 的实跑里 5 道题 0 张卡命中，旧渲染因此一个字都没发。
    """
    cards = start_cards(kind, category, tags, limit=limit, available=available)
    parts = [p for p in (playbook(kind), HEADER if cards else "") if p]
    parts.extend("- " + card.text for card in cards)
    return "\n".join(parts)
