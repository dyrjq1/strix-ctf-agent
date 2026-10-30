"""A.I.G 规则库本地化：把上游 YAML 转成本项目运行时的两个 JSON 索引。

做两件事
--------
1. **指纹规则**（上游 ``data/fingerprints``，nuclei 风格但不完全兼容）
   → 抽出 HTTP 探测路径、匹配条件、版本提取正则
2. **漏洞规则**（上游 ``data/vuln``，自定义 version 表达式）
   → 复制原文并建立「组件名 → 规则列表」索引

产物（写到输出目录）::

    fingerprints.json   每条规则一个组件
    vuln_index.json     组件索引
    vuln/               规则原文（运行时由 agent 按需读取）

为什么转成 JSON
---------------
冷启动快（Python 读 JSON 是内置加速，读 YAML 要 C 扩展）；
运行时不依赖 PyYAML（镜像里能少一个依赖就少一个坑）。转换只在开发期跑一次。

为什么不装 A.I.G 本体
--------------------
它需要 docker compose + 4 GB 内存 + Web UI，在 CTFY「每题一个短命容器」
的模型下根本起不来。只取规则。

不规整数据的处理
----------------
上游数据有三处坑，本文件的主要篇幅都在处理它们：

1. 部分规则放在子目录里（如 ``comfyui/comfyui.yaml``）→ 必须递归遍历
2. ``matchers`` 有两种写法：dict 列表，或直接一个字符串 ``body="xxx"``
3. ``version`` 是与 ``http`` 并列的顶层块，不是 ``http`` 里的字段
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Final

#: 宽松匹配 ``type="value"`` 里的类型名。值可能含转义引号，
#: 所以值的部分用 ``"(?:[^"\\]|\\.)*"`` 而不是 ``"[^"]*"``。
_COMPACT: Final = re.compile(
    r'(body|word|regex|status|header)\s*=\s*("(?:[^"\\]|\\.)*"|\d+)'
)

#: 一个 path 里可能的模板变量：``{{var}}`` 与 ``{var}``。
_TMPL: Final = re.compile(r"\{\{[^}]*\}\}|\{[^}]*\}")


def norm_probe(path: str | None) -> str | None:
    """把指纹规则里的路径规范化，去掉模板变量和查询串。

    ``/v1/models/{id}`` → ``/v1/models``
    ``/api/v1?foo={{bar}}`` → ``/api/v1``

    我们没有靶机的具体 ID，带模板变量的路径没法直接请求；去掉变量后
    往往仍能触发服务响应，足够做指纹判断。

    Args:
        path: 规则里的原始 path。

    Returns:
        规范化后的绝对路径；输入为空返回 ``None``。
    """
    if not path:
        return None
    p = str(path).split("?")[0]
    # 顺序很重要：先处理 {{ }} 再处理单层 { }，反了会残留花括号。
    # 用一个正则同时匹配两种形式即可保证「长优先」。
    p = _TMPL.sub("", p)
    p = re.sub(r"/+", "/", p)  # 变量删掉可能留下 '//'
    # 删掉尾部变量会留下尾斜杠（'/v1/models/{id}' → '/v1/models/'）。
    # 真实接口几乎都是不带尾斜杠的形式，留着会 404 或走错路由。
    if len(p) > 1:
        p = p.rstrip("/") or "/"
    if not p.startswith("/"):
        p = "/" + p
    return p or "/"


def _ungroup(g: Any) -> int:
    """把 extractor 的 ``group`` 字段归一成 int。

    上游有的写 ``group: 1``，有的写 ``group: [1]``。

    Args:
        g: 原始值。

    Returns:
        分组号，默认 1。
    """
    if isinstance(g, list):
        g = g[0] if g else 1
    try:
        return int(g) if g is not None else 1
    except (TypeError, ValueError):
        return 1


def _parse_compact(m: str) -> list[dict[str, Any]]:
    """解析紧凑写法 ``body="a"`` / ``word="x","y"`` / ``status=200``。

    【踩过的坑一】早期版本用 ``"[^"]*"`` 匹配值，遇到 ``body="\\"checks\\": "``
    时把值截断成 ``\\``，导致所有 JSON 页面都命中。现在值用
    ``"(?:[^"\\\\]|\\\\.)*"`` 匹配，转义引号被完整吃进去。

    【踩过的坑二】匹配后的值不能 ``.strip()``。``body="\\"checks\\": "`` 的值
    末尾那个空格是特征的一部分，只保留逗号分隔的分割，不碰首尾空白——
    否则规则里的特征串和真实响应永远差一个空格，悄悄漏报。

    Args:
        m: 紧凑写法原文。

    Returns:
        matcher 列表。
    """
    out: list[dict[str, Any]] = []
    neg = "!negative" in m
    for typ, val in _COMPACT.findall(m):
        # 去掉最外层引号，还原转义；不做 strip——空白可能是有意义的特征
        raw = val.strip('"').replace('\\"', '"').replace("\\\\", "\\")
        if typ == "word" and "," in raw:
            vals = [v.strip().strip("'\"") for v in raw.split(",")]
        else:
            vals = [raw]
        out.append({"type": typ, "value": [v for v in vals if v], "negative": neg})
    return out


def extract_fingerprints(src: Path) -> list[dict[str, Any]]:
    """解析全部指纹 YAML，产出结构化列表。

    Args:
        src: 上游 ``data/fingerprints`` 目录。

    Returns:
        组件列表，每项含 ``component / vendor / probes / keywords`` 等。
        单条规则解析失败只跳过该条，不中断整体。
    """
    import yaml  # 仅构建期依赖

    out: list[dict[str, Any]] = []
    files: list[Path] = []
    # 递归收集——早期版本只用 listdir 扫一层，漏掉了 comfyui 等 4 个嵌套规则
    for root, _, fs in os.walk(src):
        for f in sorted(fs):
            if f.endswith((".yaml", ".yml")):
                files.append(Path(root) / f)

    for full in sorted(files):
        name = str(full.relative_to(src))
        try:
            d = yaml.safe_load(full.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001 — 单条坏规则不该拖垮整库
            print(f"[skip] {name}: {e}")
            continue
        if not isinstance(d, dict) or "http" not in d:
            continue
        info = d.get("info") or {}
        probes: list[dict[str, Any]] = []
        keywords: list[str] = []

        # 指纹块（http）+ 版本探测块（version，顶层独立），统一进 probes，
        # 用 kind 区分：fp = 命中判定，ver = 只取版本
        blocks = [("fp", b) for b in (d.get("http") or [])] + [
            ("ver", b) for b in (d.get("version") or [])
        ]
        for kind, block in blocks:
            if not isinstance(block, dict):
                continue
            path = norm_probe(block.get("path"))
            if not path:
                continue
            entry: dict[str, Any] = {
                "path": path,
                "method": str(block.get("method") or "GET").upper(),
                "kind": kind,
            }
            # 上游两种拼写都出现过，且可能是单个 dict 而非列表
            extractors = block.get("extractor") or block.get("extractors") or []
            if isinstance(extractors, dict):
                extractors = [extractors]

            for m in block.get("matchers") or []:
                if isinstance(m, str):
                    entry.setdefault("matchers", []).extend(_parse_compact(m))
                    continue
                if not isinstance(m, dict):
                    continue
                for key in ("body", "word", "regex", "status", "header"):
                    if key in m:
                        vals = m[key]
                        vals = [vals] if isinstance(vals, str) else list(vals)
                        entry.setdefault("matchers", []).append(
                            {
                                "type": key,
                                "value": [str(v) for v in vals],
                                "negative": bool(m.get("negative")),
                            }
                        )

            for ex in extractors:
                if isinstance(ex, dict) and ex.get("regex"):
                    entry["version_regex"] = ex["regex"]
                    entry["version_group"] = _ungroup(ex.get("group"))
                    # Dify 的版本在响应头 X-Version，part 字段决定去哪找
                    entry["version_part"] = str(ex.get("part") or "body").lower()
                    if ex.get("name"):
                        entry["version_header"] = str(ex["name"]).lower()
                    break  # 一条规则只取第一个提取器

            probes.append(entry)
            for mm in entry.get("matchers", []):
                if mm["type"] in ("body", "word"):
                    keywords.extend(mm["value"])

        if not probes:
            continue
        out.append(
            {
                # 组件名取文件名：product 字段经常是作者/厂商（如 comfyanonymous），
                # 早期用 product 命名，出现了 "comfyui/comfyui" 这种诡异名字
                "component": full.stem,
                "vendor": (info.get("metadata") or {}).get("vendor"),
                "product": info.get("product"),
                "rule_file": name,
                "display": info.get("name"),
                "probes": probes,
                "keywords": sorted(set(keywords)),
                "has_version_detect": any("version_regex" in p for p in probes),
            }
        )
    return out


def extract_vulns(src: Path, out_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """复制漏洞规则原文，并建立「组件 → 规则概要」索引。

    规则原文照抄不加工：``details`` / ``references`` 里常有利用细节，
    运行时 agent 会直接去读这些文件，转换反而会丢信息。
    组件名取规则所在目录名（上游就是这么组织的）。

    Args:
        src: 上游 ``data/vuln`` 目录。
        out_dir: 输出根目录，原文复制到其下的 ``vuln/``。

    Returns:
        组件名 → 规则索引列表。
    """
    import yaml  # 仅构建期依赖

    dst = out_dir / "vuln"
    if dst.is_dir():
        shutil.rmtree(dst)  # 全量重建，避免上游删掉的规则残留
    shutil.copytree(src, dst)

    index: dict[str, list[dict[str, Any]]] = {}
    for root, _, files in os.walk(dst):
        for f in sorted(files):
            if not f.endswith((".yaml", ".yml")):
                continue
            p = Path(root) / f
            try:
                d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            except Exception:  # noqa: BLE001
                continue
            info = d.get("info") or {}
            comp = p.parent.name
            index.setdefault(comp, []).append(
                {
                    # 相对路径：换机器、挂载点变化后仍能定位
                    "file": str(p.relative_to(out_dir)),
                    "cve": info.get("cve"),
                    "severity": str(info.get("severity") or "").lower(),
                    "summary": str(info.get("summary") or "")[:200],  # 截断，索引要小
                    "rule": str(d.get("rule") or "").strip(),
                }
            )
    # 排序保证多次构建产物字节一致（便于 git diff 审阅规则变化）
    for v in index.values():
        v.sort(key=lambda r: (r.get("cve") or "", r["file"]))
    return index


def build(aig_data: Path, out_dir: Path) -> dict[str, int]:
    """执行完整构建。

    Args:
        aig_data: A.I.G 仓库的 ``data/`` 目录。
        out_dir: 输出目录。

    Returns:
        统计信息，便于打印与断言。

    Raises:
        FileNotFoundError: 上游 ``fingerprints`` 或 ``vuln`` 子目录缺失。
    """
    fp_src = aig_data / "fingerprints"
    vuln_src = aig_data / "vuln"
    for need in (fp_src, vuln_src):
        if not need.is_dir():
            raise FileNotFoundError(f"上游目录缺失：{need}")

    out_dir.mkdir(parents=True, exist_ok=True)

    fp = extract_fingerprints(fp_src)
    (out_dir / "fingerprints.json").write_text(
        # ensure_ascii=False：保留中文摘要，省体积
        json.dumps(fp, ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    idx = extract_vulns(vuln_src, out_dir)
    (out_dir / "vuln_index.json").write_text(
        json.dumps(idx, ensure_ascii=False),
        encoding="utf-8",
    )
    return {
        "fingerprints": len(fp),
        "with_version_detect": sum(f["has_version_detect"] for f in fp),
        "components_with_vulns": len(idx),
        "vuln_rules": sum(len(v) for v in idx.values()),
    }


if __name__ == "__main__":
    import sys

    aig = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/aiggit/data")
    out = Path(sys.argv[2] if len(sys.argv) > 2 else str(Path(__file__).parent / "data"))
    stats = build(aig, out)
    for k, v in stats.items():
        print(f"{k}: {v}")
