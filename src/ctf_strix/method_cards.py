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
    """One method card: the tags that select it and its fixed text."""

    keys: frozenset[str]
    text: str


def _card(keys: str, text: str) -> Card:
    return Card(frozenset(k.strip() for k in keys.split(",") if k.strip()), text)


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
        "idor,broken_access_control,mass_assignment,2fa_bypass,account_merge",
        "越权：两个账号互换同名资源 id，看是否 200 且内容不同；`traffic_list` 回看已发请求里的 id/role 字段。两个账号放两个具名会话（session 参数分别写 alice 与 bob），否则后登录的会把前一个的 cookie 覆盖掉。",
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


def render(
    tags: Iterable[str] | None,
    kind: str | None = None,
    available: Collection[str] | None = None,
) -> str:
    """Render the block for ``user_instructions``; empty string when nothing hits.

    Cards are appended in priority order and the loop stops before the block
    would exceed :data:`MAX_CHARS`, so the lowest-priority cards are the ones
    dropped.  A run with no matching card injects nothing at all.
    """
    cards = select(tags, kind, available=available)
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
