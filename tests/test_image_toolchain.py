"""镜像 A 档工具面的三层守卫：锁、构建期自检、运行期 import。

这些断言回答的是"镜像里有没有这个包、依赖闭包是否自洽"，不回答
"装了就能解出某题"（docs/30 的边界）。动态闭包校验见
``docker/check_toolchain.sh``；这里保留静态清单，防止 lock 被
误删条目后脚本又恰好没跑。
"""

from __future__ import annotations

import importlib
import importlib.util
import io
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "requirements.lock"

#: A 档根包。版本是本次落地时 py3.12 manylinux wheel 的实测版本。
A_TIER_ROOTS = {
    "pycryptodome": "4.3.0",
    "pycryptodomex": "3.24.1",
    "z3-solver": "4.15.4.0",
    "pillow": "12.2.0",
    "pwntools": "4.15.0",
}

#: B-tier roots added for crypto big-int math, audio/spectrograms, stego
#: arrays, forensic file parsing, and (pack C) pcap crafting, radare2
#: bridging and Reed-Solomon error correction.  angr/fpylll are excluded.
B_TIER_ROOTS = {
    "numpy": "2.2.6",
    "sympy": "1.14.0",
    "gmpy2": "2.3.2",
    "scipy": "1.16.3",
    "matplotlib": "3.11.2",
    "pefile": "2024.8.26",
    "yara-python": "4.5.4",
    "segno": "1.6.6",
    "dnslib": "0.9.26",
    # Pack C: zero hard dependencies, so B_TIER_CLOSURE is unchanged -- only
    # the expected pin count in b_tier_closure.txt grows by these three.
    "scapy": "2.8.0",
    "r2pipe": "2.1.0",
    "reedsolo": "1.7.0",
}

#: New transitive deps pulled in by the B-tier roots.  ``packaging``,
#: ``pillow`` and ``python-dateutil`` already live in the A-tier manifest, so
#: the build-time check merges both manifests.
B_TIER_CLOSURE = frozenset(
    {
        "mpmath",
        "contourpy",
        "cycler",
        "fonttools",
        "kiwisolver",
        "pyparsing",
    }
)

#: pwntools 4.15.0 的完整传递闭包（含条件依赖）。
#: ``pip download -r`` 实测 39 个 wheel（含 pwntools 自身）；
#: 其中 15 个是 lock 原有的重叠项。``pip`` 是 base image 自带的安装器，
#: 不写进 lock：``--no-deps`` 安装中途替换 pip 没有收益，还会让构建期
#: 安装器版本漂移。
PWNTOOLS_CLOSURE = frozenset(
    {
        "bcrypt",
        "capstone",
        "certifi",
        "cffi",
        "charset-normalizer",
        "colorama",
        "colored-traceback",
        "cryptography",
        "idna",
        "intervaltree",
        "invoke",
        "mako",
        "markupsafe",
        "packaging",
        "paramiko",
        "plumbum",
        "psutil",
        "pycparser",
        "pyelftools",
        "pygments",
        "pynacl",
        "pyserial",
        "pysocks",
        "python-dateutil",
        "requests",
        "ropgadget",
        "rpyc",
        "six",
        "sortedcontainers",
        "typing-extensions",
        "unicorn",
        "unix-ar",
        "urllib3",
        "zstandard",
    }
)

_MODULE_PINS = {
    "Crypto": "pycryptodome",
    "Cryptodome": "pycryptodomex",
    "PIL": "pillow",
    "pwn": "pwntools",
    "z3": "z3-solver",
    "numpy": "numpy",
    "sympy": "sympy",
    "gmpy2": "gmpy2",
    "scipy": "scipy",
    "matplotlib": "matplotlib",
    "pefile": "pefile",
    "yara": "yara-python",
    "segno": "segno",
    "dnslib": "dnslib",
    "requests": "requests",
    "capstone": "capstone",
    "unicorn": "unicorn",
    "paramiko": "paramiko",
    "rpyc": "rpyc",
    "plumbum": "plumbum",
}

#: ``from PIL import Image`` yields ``PIL`` then ``Image``; only the root
#: namespace of a dotted path is a distribution.  The second group catches the
#: imported *names* so they can be checked against the root package's ``__all__``
#: rather than mistaken for top-level modules.
_IMPORT_RE = re.compile(
    r"\b(?:from\s+([A-Za-z_][\w.]*)\s+import\s+([A-Za-z_][\w.]*)|import\s+([A-Za-z_][\w.]*))"
)
_DYNAMIC_MODULES = ("Crypto", "Cryptodome", "PIL", "pwn", "z3")
_HAVE_IMAGE_MODULES = all(
    importlib.util.find_spec(name) is not None for name in _DYNAMIC_MODULES
)


def _pins() -> dict[str, str]:
    """Parse ``name==version`` lines; the lock is a flat env snapshot."""
    pins: dict[str, str] = {}
    for line in LOCK.read_text(encoding="ascii").splitlines():
        name, version = line.split("==", 1)
        pins[name] = version
    return pins


def test_lock_pins_the_a_tier_roots() -> None:
    pins = _pins()
    for name, version in A_TIER_ROOTS.items():
        assert pins.get(name) == version, f"{name} is not pinned at {version}"


def test_pwntools_transitive_closure_is_fully_pinned() -> None:
    """``--no-deps`` turns every missing transitive pin into a runtime import error."""
    pins = _pins()
    missing = sorted(name for name in PWNTOOLS_CLOSURE if name not in pins)
    assert not missing, "pwntools closure missing from lock: " + ", ".join(missing)


def test_lock_pins_the_b_tier_roots() -> None:
    pins = _pins()
    for name, version in B_TIER_ROOTS.items():
        assert pins.get(name) == version, f"{name} is not pinned at {version}"


def test_b_tier_transitive_closure_is_fully_pinned() -> None:
    """``--no-deps`` also means every B-tier transitive pin must be present."""
    pins = _pins()
    missing = sorted(name for name in B_TIER_CLOSURE if name not in pins)
    assert not missing, "B-tier closure missing from lock: " + ", ".join(missing)


def test_b_tier_roots_do_not_drag_excluded_heavyweights() -> None:
    """angr/fpylll were an explicit decision; a pin sneaking in is a regression."""
    pins = _pins()
    for name in ("angr", "fpylll"):
        assert name not in pins, f"{name} was excluded from this batch by decision"


def test_lock_is_sorted_unique_and_only_exact_pins() -> None:
    text = LOCK.read_text(encoding="ascii")
    assert "\r" not in text, "lock must keep its original LF line endings"
    assert text.endswith("\n")
    lines = text.splitlines()
    names = [line.split("==", 1)[0] for line in lines]
    assert names == sorted(names, key=str.lower), "lock order drifted"
    assert len(names) == len(set(names)), "duplicate package in lock"
    for line in lines:
        assert re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", line), line


def test_dockerfile_runs_the_toolchain_check_after_installing() -> None:
    """``--no-deps`` 的闭包缺口必须在构建期炸，而不是等比赛里 import 才炸。"""
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert "pip install --no-deps -r /app/requirements.lock" in dockerfile
    assert "COPY docker/check_toolchain.sh /app/docker/check_toolchain.sh" in dockerfile
    assert "COPY docker/a_tier_closure.txt /app/docker/a_tier_closure.txt" in dockerfile
    assert "COPY docker/b_tier_closure.txt /app/docker/b_tier_closure.txt" in dockerfile
    assert "bash /app/docker/check_toolchain.sh" in dockerfile

    install = dockerfile.index("pip install --no-deps -r /app/requirements.lock")
    check = dockerfile.index("bash /app/docker/check_toolchain.sh")
    assert check > install, "toolchain check must run after the install"
    copy_b = dockerfile.index("COPY docker/b_tier_closure.txt")
    assert copy_b < check, "the B-tier manifest must be in the image before the check"


def test_docker_check_script_checks_metadata_and_imports() -> None:
    script = (ROOT / "docker" / "check_toolchain.sh").read_text(encoding="utf-8")
    assert "pip check" in script
    matches = re.findall(r"MODULES = \(([^)]*)\)", script)
    assert len(matches) == 2, "expected an A-tier and a B-tier module list"
    listed = set()
    for group in matches:
        listed |= set(re.findall(r'"([^"]+)"', group))
    for module in ("Crypto", "Cryptodome", "z3", "PIL", "pwn"):
        assert module in listed, f"check_toolchain.sh does not smoke-test {module}"
    for module in B_TIER_ROOTS:
        namespace = {"yara-python": "yara", "matplotlib": "matplotlib"}.get(module, module)
        assert namespace in listed, f"check_toolchain.sh does not smoke-test {namespace}"
    assert "missing namespaces" in script, "no negative branch: a missing module would be silent"
    assert "b_tier_closure.txt" in script, "B-tier manifest is never checked"
    # CB review: MODULES lists can drift from the real import statements;
    # deleting an import while keeping the list would otherwise stay green.
    for stmt in (
        "import r2pipe",
        "from reedsolo import RSCodec",
        "from scapy.all import IP, TCP",
    ):
        assert stmt in script, f"check_toolchain.sh lost its real import: {stmt}"


def test_closure_manifest_matches_the_lock() -> None:
    """构建期核对用的闭包清单必须与 lock 完全一致，否则检查会失效或误报。"""
    pins = _pins()
    manifests = {
        "a_tier_closure.txt": len(PWNTOOLS_CLOSURE) + len(A_TIER_ROOTS),
        "b_tier_closure.txt": len(B_TIER_CLOSURE) + len(B_TIER_ROOTS),
    }
    for filename, expected in manifests.items():
        lines = [
            line for line in (ROOT / "docker" / filename)
            .read_text(encoding="ascii").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        assert len(lines) == expected, f"{filename} pin count drifted"
        for line in lines:
            name, version = line.split("==", 1)
            assert pins.get(name) == version, f"{filename} drifted for {name}"


def test_dockerfile_has_no_comment_inside_a_continued_run() -> None:
    """``RUN a; \\`` 后面接一行普通 ``#`` 注释会终止指令，构建直接报错。"""
    in_run = False
    for number, line in enumerate(
        (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8").splitlines(), 1
    ):
        if line.startswith("RUN "):
            in_run = line.rstrip().endswith("\\")
            continue
        if not in_run:
            continue
        assert not line.lstrip().startswith("#"), f"Dockerfile:{number}: comment inside RUN"
        in_run = line.rstrip().endswith("\\")


def test_image_namespaces_import_and_work() -> None:
    """Build-time import is necessary; this also exercises one real call each."""
    if not _HAVE_IMAGE_MODULES:
        pytest.skip("host venv is not the image; docker/check_toolchain.sh covers this in CI")

    Crypto = importlib.import_module("Crypto")
    Cryptodome = importlib.import_module("Cryptodome")
    z3 = importlib.import_module("z3")
    PIL = importlib.import_module("PIL")
    pwn = importlib.import_module("pwn")

    from Crypto.Cipher import AES
    from Cryptodome.Cipher import AES as AESX
    from PIL import Image

    key = b"0" * 16
    plain = b"0123456789abcdef"
    assert AES.new(key, AES.MODE_ECB).decrypt(
        AES.new(key, AES.MODE_ECB).encrypt(plain)
    ) == plain
    assert AESX.new(key, AESX.MODE_ECB).decrypt(
        AESX.new(key, AESX.MODE_ECB).encrypt(plain)
    ) == plain

    x = z3.Int("x")
    solver = z3.Solver()
    solver.add(x > 3, x < 9, x % 2 == 0)
    assert solver.check() == z3.sat
    assert solver.model()[x].as_long() == 4

    image = Image.new("RGB", (4, 4), (1, 2, 3))
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    buffer.seek(0)
    reopened = Image.open(buffer)
    assert reopened.size == (4, 4)
    assert reopened.getpixel((0, 0)) == (1, 2, 3)

    assert len(pwn.cyclic(64)) == 64
    assert pwn.cyclic_find(pwn.cyclic(64)[16:20]) == 16

    # 这些是 pwntools 的传递依赖，单独 import 一次，避免只测到顶层包。
    for module in ("capstone", "unicorn", "ropgadget", "paramiko", "plumbum", "rpyc"):
        importlib.import_module(module)

    assert Crypto.__version__ and Cryptodome.__version__
    assert PIL.__version__ and z3.get_version_string()


def test_next_hints_only_import_stdlib_or_locked_modules() -> None:
    """``_NEXT`` 里的 Python 片段也必须能在镜像里跑。

    这条和 ``test_file_triage.py`` 的二进制白名单互补：那条管 shell 命令，
    这条管 ``python3 -c "from PIL import ..."`` 这类导入。新增提示若引用了
    lock 里没有的模块，测试会先红，而不是等模型在比赛里拿到 ImportError。
    """
    from ctf_strix import file_triage as ft

    pins = _pins()
    stdlib = set(sys.stdlib_module_names)
    bad: list[str] = []
    for family, hint in ft._NEXT.items():
        for span in re.findall(r"`([^`]+)`", hint):
            for from_mod, from_name, plain_mod in _IMPORT_RE.findall(span):
                module = from_mod or plain_mod
                root = module.split(".", 1)[0]
                if root in stdlib:
                    continue
                pin = _MODULE_PINS.get(root)
                if pin is None or pin not in pins:
                    bad.append(f"{family}: {root} (pin={pin})")
    assert not bad, "decision table imports modules the image does not install:\n" + "\n".join(bad)


def test_image_families_offer_the_locked_image_library() -> None:
    """Pillow is the new image primitive; the two image families must name it."""
    from ctf_strix import file_triage as ft

    assert "pillow" in _pins()
    for family in ("png", "jpeg"):
        assert "PIL" in ft._NEXT[family], f"{family} hint never mentions Pillow"


def test_skill_packs_do_not_tell_the_model_to_pip_install() -> None:
    """No internet: a ``pip install`` line is a guaranteed wasted turn.

    The skill body may still explain that installing fails; what it must not do
    is present an install command as the prerequisite.

    ``skillpack.index_skills()`` registers ``<category>/<category>.md``, so
    that is the only skill document the model reads and the only one worth
    policing here.
    """
    offenders = []
    pack = ROOT / "src" / "ctf_strix" / "skills_strix"
    paths = sorted(
        p for p in pack.glob("*/*.md") if p.name == p.parent.name + ".md"
    )
    for path in paths:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "pip install" in line:
                offenders.append(f"{path.parent.name}/{path.name}:{number}: {line.strip()}")
    assert not offenders, "skills still require pip:\n" + "\n".join(offenders)


def test_prompt_environment_lists_what_the_image_really_has() -> None:
    """The Environment block must match the lock, not the upstream wish list."""
    from ctf_strix import prompt as prompt_mod

    text = prompt_mod._CORE
    pins = _pins()
    expected = {
        "numpy": "numpy",
        "sympy": "sympy",
        "gmpy2": "gmpy2",
        "scipy": "scipy",
        "matplotlib": "matplotlib",
        "pefile": "pefile",
        "yara": "yara-python",
        "segno": "segno",
        "dnslib": "dnslib",
        "Crypto": "pycryptodome",
        "Cryptodome": "pycryptodomex",
        "z3": "z3-solver",
        "PIL": "pillow",
        "pwn": "pwntools",
    }
    for namespace, pin in expected.items():
        assert pin in pins, f"prompt advertises {namespace} but {pin} is not pinned"
        assert f"`{namespace}`" in text, f"Environment omits installed {namespace}"

    lowered = text.lower()
    # RT-1: the offline line reads "Internet: **none**; anything else cannot
    # be installed".  It deliberately does not start with "- No ", because
    # tests/test_env_claims.py parses "- No a, b, c;" as a tool list.
    assert "internet: **none**" in lowered
    assert "cannot be installed" in text
    assert "plain Python" in text or "python3" in text
    assert "nohup" in text, "long-task guidance is missing"
    assert "write_stdin" in text, "long-task guidance is missing"


def test_prompt_environment_is_free_of_task_specifics() -> None:
    """Naming test: the block must read as image truth, never as a past failure."""
    from ctf_strix import prompt as prompt_mod

    text = prompt_mod._CORE
    assert not re.search(r"FLAG\{", text)
    ipv4 = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    assert set(ipv4) <= {"127.0.0.1"}, f"task-specific IP leaked: {ipv4}"
    assert "/admin" not in text.lower()
    assert "http://" not in text and "https://" not in text
