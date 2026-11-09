"""把 CTF 技能包接进 strix 的 ``load_skill``。

## 为什么需要这一层，而不是直接 ``register_skill_dir(PACK_DIR)``

技能包里 194 个 md，但**只有 13 个是技能**——每个分类一个索引 ``<分类>/<分类>.md``，
其余 181 个多为索引指向的参考子文件（含 10 个 SKILL.md 维护文档），除索引外都不注册。

strix 的 ``get_available_skills()`` 会把注册目录里**每一层 ``<分类>/*.md``**
都当成技能，逐条写进 system prompt 的 ``<available_skills>`` 块。实测：

- 注册整包：149 条进 prompt（历史实测 145 条 ≈ 8.5k 字符 × 每次 LLM 调用 × 每个 agent；口径差 4 条为此后新增 md）；
- 只注册 13 个索引：13 条（历史实测 12 条 ≈ 3k 字符）。

prompt 是**每个 agent、每次调用**都要付的成本，而多出来的 136 条对模型毫无信息量
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

    约定：每个分类目录里有且只有一个 ``<分类>/<分类>.md``。用它当索引，而不是
    ``SKILL.md``——有些分类两种都有，``SKILL.md`` 是上游遗留的重复文件。

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
        # 只认 <分类>/<分类>.md。SKILL.md / README.md 一律跳过：前者是重复索引，
        # 后者是包说明，两者进 prompt 都只是噪音。
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


def render(path: Path, ref: str, category: str) -> str:
    """读索引文件并插入路径提示（frontmatter 保持原位）。

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
        return _hint(ref, category) + text
    head = text[: m.end()]
    body = text[m.end() :]
    return head + _hint(ref, category) + mask_flags(body)


#: 单个索引（渲染后、落盘前）的字节上限。超过即在 stage() 里截断并追加显式
#: 标记行——绝不 raise：比赛一局定生死，索引超限不该弄崩一道题。
#: 单测/CI 里另有一条 strict 闸（源索引原始字节 ≤ 此值，见 tests/test_skillpack.py），
#: 把超标挡在进仓库之前；这里是运行时兜底。
INDEX_MAX_BYTES: int = 8192


def _index_cap() -> int:
    """读 ``CTF_INDEX_CAP``（调试放宽/收紧用），未设或非法时回默认值。"""
    import os

    raw = os.environ.get("CTF_INDEX_CAP")
    if not raw:
        return INDEX_MAX_BYTES
    try:
        return int(raw)
    except ValueError:
        return INDEX_MAX_BYTES


def _cap_index(body: str, ref: str, category: str, cap: int) -> str:
    """运行时闸：渲染后的索引超 *cap* 字节就截断，尾部追加显式标记行。

    标记行带 L3 子文件路径提示：被截掉的章节本来就有子文件兜着，渐进披露
    （L2 索引 → L3 子文件）不因截断而断链。不是静默截断。

    Returns:
        截断后的文本；不超限时原样返回。结果总字节数 ≤ *cap*。
    """
    marker = (
        f"\n\n> [INDEX TRUNCATED at {cap}B: remaining sections live in subfiles "
        f"under `{ref}/{category}/`; read them with exec_command (`cat`/`sed -n`).]\n"
    )
    budget = max(cap - len(marker.encode("utf-8")), 0)
    encoded = body.encode("utf-8")
    if len(encoded) <= budget:
        return body
    cut = encoded[:budget]
    nl = cut.rfind(b"\n")
    if nl > 0:
        cut = cut[: nl + 1]
    # 按整行切（UTF-8 续字节不含 0x0A，行边界即字符边界）；ignore 只是兜底。
    text = cut.decode("utf-8", errors="ignore").rstrip("\n")
    return text + marker


def stage(ref: str | None = None, pack: Path | None = None) -> Path:
    """生成只含索引的临时注册目录。

    Args:
        ref: 子文件根路径，默认 :func:`ref_root`。
        kind: 题型（web/file/tcp/...）；只渲染该题型能执行的工具方向。
        pack: 技能包根目录，默认 :data:`PACK_DIR`。

    Returns:
        注册目录（``<tmp>/<分类>/<分类>.md``）。技能包缺失时返回一个空目录——
        调用方据此判断"要不要注册"，而不是拿到异常。索引渲染后超过
        :data:`INDEX_MAX_BYTES`（``CTF_INDEX_CAP`` 可覆盖）按 :func:`_cap_index`
        截断并追加标记行，绝不 raise。

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
        body = _cap_index(body, ref_path, category, _index_cap())
        # 二进制落盘：字节闸算的就是落盘字节；文本模式在 Windows 会把 \n 翻译成
        # \r\n，闸口就形同虚设。顺带保证 staged 副本恒为 LF。
        (out_dir / f"{name}.md").write_bytes(body.encode("utf-8"))
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


def prompt_hint(
    names: list[str] | None = None,
    ref: str | None = None,
    kind: str | None = None,
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

    Returns:
        多行指令；没有可用技能时返回空串。
    """
    from ctf_strix import routing

    skill_names = names if names is not None else [f"{c}/{n}" for c, n, _ in index_skills()]
    if not skill_names:
        return ""
    return routing.render(skill_names, ref or ref_root(), kind=kind)
