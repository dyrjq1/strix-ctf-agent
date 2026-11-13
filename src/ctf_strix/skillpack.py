"""把 CTF 技能包接进 strix 的 ``load_skill``。

## 为什么需要这一层，而不是直接 ``register_skill_dir(PACK_DIR)``

技能包里两层 md 实测 139 个、递归共 236 个，但**只有 13 个是技能**——
每个分类一个索引 ``<分类>/<分类>.md``，其余 126 个两层文件是索引指向的参考子文件，
除索引外都不注册。

strix 的 ``get_available_skills()`` 会把注册目录里**每一层 ``<分类>/*.md``**
都当成技能，逐条写进 system prompt 的 ``<available_skills>`` 块。实测：

- 注册整包：139 条进 prompt（历史实测 145 条 ≈ 8.5k 字符 × 每次 LLM 调用 × 每个 agent；
  此后 +4 条新增、−10 个 SKILL.md 副本，净 −6）；
- 只注册 13 个索引：13 条（历史实测 12 条 ≈ 3k 字符）。

prompt 是**每个 agent、每次调用**都要付的成本，而多出来的 126 条对模型毫无信息量
（名字就是文件名，描述为空）。所以这里只暴露索引，子文件走 ``read_file``。

## 代价与补偿

只暴露索引意味着索引里的相对链接 ``[heap-techniques.md](heap-techniques.md)``
对模型没有可用路径。所以每个索引在装载时会被插进一行路径提示，指向
:func:`ref_root` —— 也就是技能包在**命名空间内**的挂载点。少了这行，模型会猜路径
（``./heap-techniques.md``、``skills/heap-techniques.md``），一次猜错就是一轮浪费。

## 为什么注册目录是临时的

索引副本要插入路径提示，而路径提示依赖运行期挂载点，不能固化进仓库。所以每次
run 在 tmpfs 里现生成一份（13 个文件、约 210 KB、耗时 10ms 量级），仓库里只留
原始技能包一份真相。
"""

from __future__ import annotations

import re
import tempfile
from collections.abc import Collection
from pathlib import Path
from typing import Any

from ctf_strix.flag_extract import CANDIDATE_RE, is_code_template, is_placeholder

#: 原始技能包（唯一真相）。目录布局 ``<分类>/<分类>.md`` + 子文件。
PACK_DIR: Path = Path(__file__).resolve().parent / "skills_strix"

#: 技能包里带真实 flag 的 writeup 有 30+ 处。它们对解题毫无用处，却是最直接的
#: 污染源：agent 一旦 ``read_file`` 到一份旧 writeup，日志里就会多出一个"看起来
#: 像答案"的 flag，``flag_extract`` 的兜底（唯一候选）会把它交上去。有的题
#: 就是这样被人工解过的旧 writeup 污染成"agent 解出"的。装载时统一抹成 ``FLAG{...}``，
#: 形态保留、内容消失；``FLAG{...}`` 又刚好命中 flag_extract 的占位符排除规则。
#:
#: ⚠️ 用的是 :data:`ctf_strix.flag_extract.CANDIDATE_RE`，与提交层同一份定义。
#: 它没有词边界：``MetaCTF{...}`` 只会匹配其中的 ``CTF{...}`` 片段，替换后
#: ``Meta`` 前缀原样留在正文里，结果是 ``MetaCTF{...}``。这是预期行为——
#: 提交层同样会把 ``MetaCTF{...}`` 截成 ``CTF{...}``，两边口径必须一致。


def mask_flags(text: str) -> str:
    """把文本里的候选答案形态抹成 ``FLAG{...}`` 占位符。

    代码示例不能改坏：技能包里有 ``print(f"Flag: flag{{{decoded}}}")`` 这类
    可执行片段，``CANDIDATE_RE`` 会截出 ``flag{{{decoded}``，直接替换会少一个
    花括号、把示例变成语法错误。

    Args:
        text: 任意技能文本。

    Returns:
        抹掉答案内容的文本；前缀大小写保持不变。
    """

    def repl(m: "re.Match[str]") -> str:
        flag = m.group(0)
        # 已经是模板的别动；代码模板（f-string / ${x} / printf / 正则类）也别动。
        if is_placeholder(flag) or is_code_template(flag):
            return flag
        return flag.split("{", 1)[0] + "{...}"

    return CANDIDATE_RE.sub(repl, text)


#: frontmatter 必须留在文件最前，所以提示只能插在 frontmatter **之后**。
_FRONTMATTER = re.compile(r"^---\s*\n.*?\n---\s*\n", re.DOTALL)


def ref_root() -> str:
    """技能包在运行期可被 ``read_file`` 读到的根路径。

    jail 里由 ``eval_sample`` 把技能包 bind 到 ``/var/ctf/jail/skills``；
    不走 jail 的本地调试直接用仓库路径。两处都必须是绝对路径——模型拿到的
    是字符串，没有 cwd 可依。

    Returns:
        绝对路径字符串。
    """
    import os

    env = os.environ.get("CTF_SKILLS_REF")
    if env:
        return env
    # 只看目录存在是不够的：jail 的挂载点在宿主侧是**空目录**（bind 只在
    # namespace 内生效），非 jail 的本地调试会拿到一个空路径，提示于是指向
    # 一个读不到子文件的地方。用"目录里有没有分类目录"当判据。
    jailed = Path("/var/ctf/jail/skills")
    if jailed.is_dir() and any(p.is_dir() for p in jailed.iterdir()):
        return str(jailed)
    return str(PACK_DIR)


#: Categories that must never be offered or registered.
#:
#: ``ctf-similar-search`` 整篇建立在 ``pip install tavily`` + ``api.tavily.com``
#: 之上，而运行期禁止出网、镜像也没有这个包。它出现在索引里只有一种效果：
#: 模型点名加载它，读到一份自己完全执行不了的方法论，然后浪费一轮。
#:
#: 这里排除而不是删目录：目录留着以便本地查询，注册面与提示面必须干净。
_EXCLUDED: frozenset[str] = frozenset({"ctf-similar-search"})


def index_skills(pack: Path | None = None) -> list[tuple[str, str, Path]]:
    """列出所有**索引**技能。

    约定：每个分类目录里有且只有一个 ``<分类>/<分类>.md``，它就是该分类的
    索引；上游原有的 ``SKILL.md`` 副本不再随包分发（见 ``THIRD_PARTY.md``）。

    Args:
        pack: 技能包根目录，默认 :data:`PACK_DIR`。

    Returns:
        ``(分类, 技能名, 文件路径)`` 列表，按分类名排序。
    """
    root = pack or PACK_DIR
    out: list[tuple[str, str, Path]] = []
    if not root.is_dir():
        return out
    for category in sorted(p for p in root.iterdir() if p.is_dir()):
        if category.name in _EXCLUDED:
            continue
        # 只认 <分类>/<分类>.md。README.md 之类的其余文件一律跳过：进 prompt
        # 只是噪音。SKILL.md 副本已从包里删除，这里也不为它留通配。
        candidate = category / f"{category.name}.md"
        if candidate.is_file():
            out.append((category.name, category.name, candidate))
    return out


def _hint(ref: str, category: str) -> str:
    """生成插进索引正文的路径提示。

    Args:
        ref: 技能包在运行期的绝对根路径。
        category: 分类名，用于拼出子文件目录。

    Returns:
        markdown 片段，末尾带两个换行，保证与正文之间有分隔。
    """
    return (
        f"> 子文件目录：`{ref}/{category}/`；`[x.md](x.md)`=`{ref}/{category}/x.md`；"
        f"`exec_command` cat/sed -n、图片 `view_image`；非技能，勿 `load_skill`；一次一个方向索引。\n\n"
    )


#: 索引正文里的相对链接 ``[摘要](相对路径)``。只取括号里的目标。
_INDEX_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")

#: 子文件清单块的起始标记。测试与调用方靠它判断清单在不在。
_FILES_MARK = "> 子文件清单"

#: 清单块的内联预算（字符）。超出就退化成 ``ls`` 指引。
#:
#: 这个数不是拍脑袋：块必须整段落在 ``context.py`` 的 head 窗口
#: （``HEAD_CHARS`` 4,800）内，而 frontmatter（实测 547–986）+ 路径提示
#: （200）已经占掉 747–1,186。实测最坏是 ctf-crypto：72 个子文件、块长 2,039，
#: 加前两者共 2,786 字符——留 2,014 的余量给索引后续增长。超过预算的清单
#: 一律不进提示：半截名单会让模型以为"文件就这些"，比不给更糟。
_FILES_MAX_CHARS = 2_400


def _files_index(text: str, ref: str, category: str) -> str:
    """从索引正文抽出它引用的子文件清单。

    **为什么需要这一块**：``context.py`` 对注入的索引做头尾封顶
    （head 4,800 / tail 2,400，``CAP_CHARS`` 8,000）。13 个索引里 8 个超过
    8,000 字符，而"子文件链接表"恰好长在中段——crypto 49,524 字符、160 条链接
    里 133 条落在被折叠区。模型于是只知道有 "crypto" 这个方向，不知道下面有
    哪些文件、该读哪一个。清单紧跟路径提示，落在 head 区间，封顶裁不到；
    实测最坏占用 2,786 字符，仍低于 head 4,800。

    只收本地 ``.md`` 目标（保留相对写法，锚点去掉），按出现顺序去重：
    ``../ctf-misc/ctf-misc.md`` 这类跨方向链接照样收，它是有效路径。

    Args:
        text: 索引正文（应为已剥掉 frontmatter 的部分）。
        ref: 技能包运行期根路径，用于超预算时的 ``ls`` 指引。
        category: 分类名，同上。

    Returns:
        以空行结尾的 markdown 块；索引没引用任何本地 md 时返回空串。
    """
    files: list[str] = []
    for line in text.split("\n"):
        for m in _INDEX_LINK.finditer(line):
            target = m.group(1).split("#", 1)[0].strip()
            if not target.endswith(".md") or "://" in target or target.startswith("mailto:"):
                continue
            if mask_flags(target) != target:
                # RISK 8：清单从未遮蔽的正文抽取（mask_flags 只作用于 body），
                # 名字本身带 flag 形态的文件不列：遮蔽会给出一个读不到的假路径，
                # 比不列更糟；模型要找仍可 ls。
                continue
            if target not in files:
                files.append(target)
    if not files:
        return ""
    listed = " ".join(f"`{name}`" for name in files)
    if len(listed) > _FILES_MAX_CHARS:
        # 名单装不下就不装：指向目录本身，一个 ls 拿到同样的信息。
        return f"{_FILES_MARK}（{len(files)} 个，超出内联预算）：`ls {ref}/{category}/`。\n\n"
    return f"{_FILES_MARK}（{len(files)}）：{listed}\n\n"


def render(path: Path, ref: str, category: str) -> str:
    """读索引文件并插入路径提示与子文件清单（frontmatter 保持原位）。

    Args:
        path: 索引文件路径。
        ref: 技能包运行期根路径。
        category: 分类名。

    Returns:
        可直接落盘的全文。

    Raises:
        OSError: 文件不可读。
    """
    text = path.read_text(encoding="utf-8")
    m = _FRONTMATTER.match(text)
    if m is None:
        return _hint(ref, category) + _files_index(text, ref, category) + text
    head = text[: m.end()]
    body = text[m.end() :]
    prefix = _hint(ref, category) + _files_index(body, ref, category)
    return head + prefix + mask_flags(body)


def stage(ref: str | None = None, pack: Path | None = None) -> Path:
    """生成只含索引的临时注册目录。

    Args:
        ref: 子文件根路径，默认 :func:`ref_root`。
        pack: 技能包根目录，默认 :data:`PACK_DIR`。

    Returns:
        注册目录（``<tmp>/<分类>/<分类>.md``）。技能包缺失时返回一个空目录——
        调用方据此判断"要不要注册"，而不是拿到异常。

    Raises:
        OSError: 临时目录不可写。
    """
    root = pack or PACK_DIR
    ref_path = ref or ref_root()
    dst = Path(tempfile.mkdtemp(prefix="ctf-skills-"))
    for category, name, path in index_skills(root):
        out_dir = dst / category
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            body = render(path, ref_path, category)
        except OSError:
            # 单个索引读不到不该让整题跑不动：少一个方向，其余照常。
            continue
        (out_dir / f"{name}.md").write_text(body, encoding="utf-8")
    return dst


def register(registry: Path | None = None, register_fn: Any | None = None) -> list[str]:
    """把索引注册进 strix，返回可用的 ``分类/分类`` 技能名。

    Args:
        registry: :func:`stage` 的产物，默认现做一份。
        register_fn: 注入点，默认 ``strix.skills.register_skill_dir``。
            显式传入便于单测。

    Returns:
        已注册的技能名列表（``分类/分类``）；技能包缺失时为空列表。
    """
    if register_fn is None:
        from strix.skills import register_skill_dir as register_fn  # type: ignore[no-redef]

    target = registry if registry is not None else stage()
    names = [f"{c}/{n}" for c, n, _ in index_skills(target)]
    if not names:
        return []
    register_fn(target)
    return names


#: ``user_instructions`` 路由段的出口上限（字符）。
#:
#: 通道所有权（CROSS-CHECK 3 落账）：``user_instructions`` 没有下游封顶——
#: ``context._cap_item`` 只分派 ``function_call_output`` / ``function_call``
#: 两类 item，从不处理 user 文本。这条通道由各生产者自律：
#: :data:`ctf_strix.method_cards.MAX_CHARS` 自律 1,200；``routing.render``
#: 有意不截断（静默丢路线 = 死方向，见 ``tests/test_routing.py`` 模块注释），
#: 其 3,000 预算由测试在开发期守；本模块的 :func:`prompt_hint` 是路由段
#: **运行期出口封顶**，上限取两个付费预算之和。今天实测最坏 2,834，不触发。
HINT_MAX_CHARS = 4_200

#: 超限截断标记：可见，不是静默——模型需要知道尾部被切了。
_HINT_CAPPED_MARK = "\n[routing hint capped] 超出上限，尾部按行截断。"


def _cap_hint(text: str) -> str:
    """出口封顶：低于上限逐字节原样；超限按行边界截断并留可见标记。

    按行而不是字符硬切：半行会把一条完整判据切成两截（``context.py`` 对
    工具输出的同类封顶因字符硬切被审查点名为 RISK 10，不重蹈）。单行文本
    超限的极端情况才退化为字符截断——没有行结构可保，保线无意义。
    """
    if len(text) <= HINT_MAX_CHARS:
        return text
    mark = _HINT_CAPPED_MARK
    room = HINT_MAX_CHARS - len(mark)
    cut = text.rfind("\n", 0, room + 1)
    if cut <= 0:
        return text[:room] + mark
    return text[:cut].rstrip() + mark


def prompt_hint(
    names: list[str] | None = None,
    ref: str | None = None,
    kind: str | None = None,
    tags: list[str] | None = None,
    available: Collection[str] | None = None,
) -> str:
    """生成写进 ``user_instructions`` 的路由契约。

    提示里没有这一块，模型会把索引当普通文本读完就动手，不会去读子文件；
    也可能一次加载两个方向索引，把上下文挤掉一半。

    内容由 :mod:`ctf_strix.routing` 提供：判据表 + 存活闸门 + 证伪要求 +
    预算复盘点。这里只负责把"已注册的技能名"和"子文件根路径"传下去，
    避免提示指向一个没装上的方向。

    Args:
        names: :func:`register` 的返回值，默认现算。
        ref: 子文件根路径，默认 :func:`ref_root`。
        kind: 题型（web/file/tcp/...）；只渲染该题型能执行的工具方向。
        tags: 题目 tags；只用于方法卡求交集，原文不进提示。
        available: 本进程实际注册的工具名；方法卡点名了未注册的工具就剔卡。
            ``None`` 关闭过滤（单测、或工具面未知时）。

    Returns:
        多行指令；路由与方法卡都为空时返回空串。
        方法卡只看 tags 与 kind，不依赖技能包是否存在。
        合并结果经 :func:`_cap_hint` 出口封顶（:data:`HINT_MAX_CHARS`）：低于
        上限逐字节不变；超限按行截断并留可见标记。
    """
    from ctf_strix import method_cards
    from ctf_strix import routing

    skill_names = names if names is not None else [f"{c}/{n}" for c, n, _ in index_skills()]
    routing_text = routing.render(skill_names, ref or ref_root(), kind=kind) if skill_names else ""
    cards_text = method_cards.render(tags, kind=kind, available=available)
    return _cap_hint("\n\n".join(part for part in (routing_text, cards_text) if part))


def tags_of(task: dict | None) -> list[str]:
    """题目 metadata 的 tags；只取 tags，不取标题与描述（零注入面）。"""
    from ctf_strix import method_cards

    return method_cards.tags_of(task)
