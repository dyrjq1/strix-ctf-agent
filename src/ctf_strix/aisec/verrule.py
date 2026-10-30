"""版本约束表达式求值器（A.I.G 自定义语法，非 PEP440 specifier）。

为什么自己写而不用 packaging.specifiers：
    A.I.G 的规则是 ``version < "0.1.38"``、``(version >= "3.0.0" && version < "4.5.11") || ...``
    这种带括号和逻辑运算符的表达式，不是 PEP 440 的 ``">=1.0,<2.0"`` 逗号分隔格式，
    ``SpecifierSet`` 直接解析会抛异常。

为什么不用 eval：
    规则来自第三方仓库，未来可能被投毒；用递归下降解析器只认白名单 token，
    遇到意外语法一律返回 False，不会执行任意代码。

支持语法::

    version <op> "1.2.3"      比较，op ∈ {<, <=, >, >=, ==, =, !=}
    A && B / A || B           逻辑与/或（&& 优先级高于 ||）
    ( ... )                   分组
    name == "value"           条件型规则（如 is_internal=="true"），值来自 ctx 字典

版本号缺失时的行为：
    规则里出现 ``version`` 但调用方没给版本 → 该原子表达式为 False（无法判定即不命中）。
    这会让「取不到版本号」的靶机丢弃所有版本类规则，是有意为之：
    宁可漏报，不可误报出题人精心构造的假象。
"""

from __future__ import annotations

import re
from typing import Any, Final

# 词法：按优先级排列，长的操作符（&&、||、>=）必须排在单字符（&、|、>）前面，
# 否则 ">=" 会被拆成 ">" 和 "="。末尾 \S 是兜底，保证任何字符都能被消费、不会死循环。
_TOKEN: Final = re.compile(r'\s*(\(|\)|&&|\|\||>=|<=|==|!=|=|<|>|"[^"]*"|[A-Za-z_][\w]*|\S)')

#: 版本比较运算符 → 判定函数。用字典而不是 if/elif 链，新增运算符只改一处。
_CMP: Final[dict[str, Any]] = {
    "<": lambda c: c < 0,
    "<=": lambda c: c <= 0,
    ">": lambda c: c > 0,
    ">=": lambda c: c >= 0,
    "==": lambda c: c == 0,
    "=": lambda c: c == 0,
    "!=": lambda c: c != 0,
}

# 预发布标记优先级：dev < alpha < beta < rc < 正式版
# 注意 a/alpha、b/beta、c/rc 是 PEP 440 允许的缩写别名，权重必须相同
_PRE: Final[dict[str, int]] = {
    "dev": 0, "snapshot": 0,
    "a": 1, "alpha": 1,
    "b": 2, "beta": 2,
    "c": 3, "rc": 3, "pre": 3, "preview": 3,
}

#: 后发布标记：1.0.post1 > 1.0。与预发布相反，缺失段要小于它。
_POST: Final[frozenset[str]] = frozenset({"post", "rev", "r", "patch", "p"})

# 哨兵：用于区分「段不存在」和「段存在且为 0」，两者语义完全不同
_MISSING: Final = object()


def tokens(expr: str) -> list[str]:
    """把表达式切成 token 列表。引号内的空格被保留（不会切断字符串）。

    Args:
        expr: 版本约束表达式原文。

    Returns:
        token 列表；括号、运算符、字符串字面量各自独立成项。
    """
    out: list[str] = []
    pos = 0
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            break
        out.append(m.group(1))
        pos = m.end()
    return out


def vtuple(v: str) -> tuple[Any, ...]:
    """把版本字符串切成可比较的段元组：``'1.53.1.dev1'`` → ``(1, 53, 1, 'dev1')``。

    数字段转 int（这样 1.10 > 1.9，字符串比较会得出相反结论），
    非数字段保留字符串，后续由 :func:`_seg_key` 赋予排序权重。

    段内「数字 + 标记」要再切一刀：``rc1`` → ``('rc', 1)``。
    不切的话 ``1.53.1rc1`` 会被当成一个整体字符串段，和 ``dev1`` 比不出序。

    Args:
        v: 版本号原文，容忍 ``v1.2.3`` 前缀。

    Returns:
        段元组，数字为 int，其余为 str。
    """
    v = str(v).strip().lstrip("vV")
    out: list[Any] = []
    for part in re.split(r"[.\-_+]", v):  # 点、连字符、下划线、加号都是合法分隔符
        if not part:
            continue
        if part.isdigit():
            out.append(int(part))
            continue
        # 'rc1' / 'dev12' → 标记 + 序号；
        # '1rc1'（来自 "1.53.1rc1" 按点切分）→ 数字 + 标记 + 序号。
        # 两种形态都要处理，否则 '1rc1' 会整体当一个字符串段，
        # 与 'dev1' 比不出序。
        m = re.fullmatch(r"(\d*)([A-Za-z]+)(\d*)", part)
        if m:
            lead, tag, num = m.groups()
            if lead:
                out.append(int(lead))
            out.append(tag.lower())
            if num:
                out.append(int(num))
        else:
            out.append(part.lower())
    return tuple(out)


def _seg_key(seg: Any) -> tuple[int, int, str]:
    """把单个版本段转成可排序的键。

    返回 ``(类别, 权重, 原文)``，类别越大越「晚」：

    - 数字段   → ``(2, 值, "")``      —— 数字段永远大于字符串段
    - 预发布段 → ``(1, 0~3, 原文)``   —— dev < alpha < beta < rc < 正式版
    - 后发布段 → ``(3, 0, 原文)``     —— ``1.0.post1`` 大于 ``1.0``
    - 其它段   → ``(1, 9, 原文)``     —— 未知标记排在所有预发布之后

    ``post`` 必须单独成一类：早期版本把它当「未知标记」放进类别 1，
    结果 ``1.0.post1 < 1.0.1`` 判成 ``1.0.post1 > 1.0.1``（因为类别 1 的对面
    是类别 2 的数字段，反而更大），已修复的版本会被报成有漏洞。
    """
    if isinstance(seg, int):
        return (2, seg, "")
    s = str(seg).lower()
    if s in _PRE:
        return (1, _PRE[s], s)
    if s in _POST:
        return (3, 0, s)
    return (1, 9, s)


def cmp_ver(a: str, b: str) -> int:
    """按 PEP 440 语义比较版本，返回 ``-1 / 0 / 1``。

    核心规则：``1.53.1 > 1.53.1rc1 > 1.53.1.dev1 > 1.53.0``

    缺失段的语义是这里唯一的难点，按对面的类型分两种情况：

    - 对面是**预发布标记**（``1.53.1`` vs ``1.53.1.dev1``）：
      缺失 = 正式版发布，**大于**任何预发布。
    - 对面是**数字段**（``1.0`` vs ``1.0.1``）：缺失按 0 处理。
      这里**必须返回 0 继续比下一段**，早期版本直接 ``return -1``，
      于是 ``version >= "1.0.0"`` 会判 1.0.0 不满足（应为满足），
      进而把已修复的版本报成「存在漏洞」。
    - 对面是**后发布标记**（``1.0`` vs ``1.2.0.post1``，跨段比较时）：
      缺失 = 正式版，**小于** post 发布。

    Args:
        a: 左侧版本。
        b: 右侧版本。

    Returns:
        -1 表示 a<b，0 表示相等，1 表示 a>b。
    """
    A, B = vtuple(a), vtuple(b)
    for i in range(max(len(A), len(B))):
        x = A[i] if i < len(A) else _MISSING
        y = B[i] if i < len(B) else _MISSING
        if x is _MISSING and y is _MISSING:
            continue
        if x is _MISSING:
            if isinstance(y, str) and y.lower() in _POST:
                return -1  # 1.0 < 1.0.post1
            if isinstance(y, str):
                return 1  # 1.0 > 1.0rc1
            if y == 0:
                continue  # 1.0 == 1.0.0，继续比后面的段
            return -1  # 1.0 < 1.0.1
        if y is _MISSING:
            if isinstance(x, str) and x.lower() in _POST:
                return 1
            if isinstance(x, str):
                return -1
            if x == 0:
                continue
            return 1
        kx, ky = _seg_key(x), _seg_key(y)
        if kx != ky:
            return -1 if kx < ky else 1
    return 0


class _Parser:
    """递归下降解析器。文法（``||`` 优先级最低）::

        expr   := and ( "||" and )*
        and    := atom ( "&&" atom )*
        atom   := "(" expr ")" | "version" op STR | IDENT op STR

    【注意】and/or 用「先算两边、再合并」的写法而非短路：
    这样右侧的语法错误会真的被解析到，而不是被短路掩盖，
    便于发现规则库自身的坏数据（调试期）。

    Args:
        toks: :func:`tokens` 的产物。
        version: 目标版本；``None`` 表示未知。
        ctx: 条件型规则的取值字典。
    """

    def __init__(self, toks: list[str], version: str | None, ctx: dict[str, Any]) -> None:
        self.t, self.i = toks, 0
        self.v, self.ctx = version, ctx

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> str | None:
        tok = self.peek()
        self.i += 1
        return tok

    def parse_or(self) -> bool:
        val = self.parse_and()
        while self.peek() == "||":
            self.take()
            val = self.parse_and() or val
        return bool(val)

    def parse_and(self) -> bool:
        val = self.parse_atom()
        while self.peek() == "&&":
            self.take()
            val = self.parse_atom() and val
        return bool(val)

    def parse_atom(self) -> bool:
        tok = self.peek()
        # 左括号：递归解析子表达式，右括号缺失时容忍（规则库里有手写不规整的）
        if tok == "(":
            self.take()
            val = self.parse_or()
            if self.peek() == ")":
                self.take()
            return val
        # 版本比较：version <op> "1.2.3"
        if tok == "version":
            self.take()
            op = self.take() or ""
            rhs = (self.take() or '""').strip('"')
            if self.v is None:
                return False  # 不知道版本就无法判定，按不命中处理
            fn = _CMP.get(op)
            return bool(fn and fn(cmp_ver(self.v, rhs)))
        # 条件型：IDENT == "value"，值从 ctx 取（如 is_internal=="true"）。
        # ctx 里取不到时 lhs=None，str(None)="none" 不会误匹配 "true"。
        name = self.take() or ""
        op = self.take() or ""
        rhs = (self.take() or '""').strip('"')
        lhs = self.ctx.get(name)
        if op in ("==", "="):
            return str(lhs).lower() == rhs.lower()
        if op == "!=":
            return str(lhs).lower() != rhs.lower()
        return False


def evaluate(expr: str | None, version: str | None = None, ctx: dict[str, Any] | None = None) -> bool:
    """求值入口。空规则返回 ``True``（表示「无版本约束」，如逻辑漏洞类规则）。

    任何解析异常都吞掉并返回 ``False``：
    规则库有上千条，单条坏规则不应让整个扫描崩溃。

    Args:
        expr: 规则表达式，可为空。
        version: 目标组件版本；``None`` 表示未取到版本。
        ctx: 条件型规则的取值字典。

    Returns:
        表达式是否成立。
    """
    expr = (expr or "").strip()
    if not expr:
        return True
    try:
        return _Parser(tokens(expr), version, ctx or {}).parse_or()
    except Exception:  # noqa: BLE001 — 坏规则必须被隔离
        return False


_CASES: Final[tuple[tuple[str, str | None, bool], ...]] = (
    ('version < "1.53.1.dev1"', "1.52.0", True),
    ('version <= "0.5.55"', "0.5.60", False),
    ('version >= "1.0.0" && version < "1.2.0"', "1.1.9", True),
    ('(version >= "3.0.0" && version < "4.5.11") || (version >= "4.6.0" && version < "4.6.4")', "4.6.2", True),
    ('(version >= "3.0.0" && version < "4.5.11") || (version >= "4.6.0" && version < "4.6.4")', "4.5.11", False),
    # 段补齐：1.0.0 必须满足 >= "1.0.0"，且 1.0 不等于 1.0.0.5
    ('version >= "1.0.0"', "1.0", True),
    ('version == "1.0.0"', "1.0", True),
    ('version < "1.0.0.5"', "1.0", True),
    # 预发布与正式版的序
    ('version > "1.53.1"', "1.53.1.dev1", False),
    ('version < "1.53.1"', "1.53.1.dev1", True),
    # 版本未知 → 一律不命中
    ('version < "9.9.9"', None, False),
    ("is_internal==\"true\"", None, True),
)


if __name__ == "__main__":
    ok = 0
    for expr, ver, want in _CASES:
        got = evaluate(expr, ver, {"is_internal": "true"})
        ok += got == want
        print(("PASS" if got == want else "FAIL"), expr[:56], "ver=", ver, "->", got)
    print(f"{ok}/{len(_CASES)}")
