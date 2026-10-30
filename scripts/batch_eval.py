"""批量评测：串行跑 N 道题，边跑边记数据。

约束（全部来自平台实测，不是假设）：
- ``max_instances_per_team_effective = 1`` → 必须串行，不能并行
- 实例 TTL 10800 s → 单题最多占这么久，超时前必须先删
- 删实例后再起新的有 30-60 s 开销

设计取舍：
- **每题一次机会**。失败就记失败，不重试——重试会污染"解题率"这个指标，
  让一个随机性高的 agent 看起来比实际好。
- **数据即时落盘**（每跑完一题就 append 到 JSONL）。今天已经被沙箱休眠
  杀过一次进程，教训是：不要等全部跑完再写文件。
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import requests
import urllib3

# 靶机普遍是自签证书，连通性探测用 verify=False。这个警告每次实例都刷两行，
# 混在结果日志里没有信息量。
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PLATFORM = "https://ctfy.tsinghua.edu.cn"

#: 题目所在 suite。批量评测会跨 suite（CTFARENA 用来做难度梯度，
#: UPLOADLABS 是已知能解的对照组），所以不能写死一个。
SUITES = {
    "UPLOADLABS": "3a5ea9fff91e4585b213c43a9d31b96e",
    "CTFARENA": "4394a10aa5d24f97a1ec3301ca718a45",
    "SQLILABS": "f2348cfef1994a8082fedeb324efdbdc",
    "AGENTBENCH": "9f613f261b68469b9c4da805197983b2",
    "GAUNTLET": "2b3aecd6540b47419d45c294def49773",
}


def suite_for(challenge_id: str) -> str:
    """按题号前缀路由到所属 suite。未知前缀直接报错，不猜。"""
    for prefix, sid in SUITES.items():
        if challenge_id.startswith(prefix):
            return sid
    msg = f"题号 {challenge_id} 的前缀不在已知 suite 表里，请先确认它属于哪个 suite"
    raise KeyError(msg)


class TunnelRequiredError(RuntimeError):
    """题目只暴露 ``*.internal`` 私有域名，评测机无隧道时无法访问。"""


#: 私有 DNS 后缀。这些域名只在题目容器的网络里能解析。
_PRIVATE_SUFFIXES = (".internal", ".local", ".lan", ".svc", ".cluster.local")


def _public_url(svc: dict) -> str | None:
    """把 platform 的 service 条目转成可直连 URL；不可直连返回 None。

    Args:
        svc: ``attack_surface.services[i]``，含 ``host`` / ``port`` / ``service_type``。

    Returns:
        ``http(s)://host[:port]/``，或 None（私有域名 / 字段缺失）。
    """
    host = (svc.get("host") or "").strip()
    if not host or host.endswith(_PRIVATE_SUFFIXES):
        return None
    scheme = "https" if svc.get("service_type") == "https" or svc.get("port") == 443 else "http"
    port = svc.get("port")
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        return f"{scheme}://{host}:{port}/"
    return f"{scheme}://{host}/"


class Client:
    """CTFY 平台最小客户端，只封装评测需要的 4 个动作。"""

    def __init__(self, token: str) -> None:
        self.token = token
        self.s = requests.Session()
        self.s.headers["Authorization"] = f"Bearer {token}"

    def launch(self, challenge_id: str, attempts: int = 5) -> str:
        """起一个实例。先兜底清理残留，再启动，平台故障时退避重试。

        Args:
            challenge_id: 题号。
            attempts: 遇到 5xx / 429 时的最大尝试次数。

        Returns:
            新实例 id。

        Raises:
            RuntimeError: 重试用尽。

        ⚠️ **起之前必须清残留。** 队伍只有一个实例槽，任何一次被 SIGKILL 的
        运行都会把实例留在 ``ready`` 状态直到 3 小时 TTL 到期。实测踩过：
        停掉一轮批量后，后续 11 题全部 429 ``team_capacity_exceeded``，
        看着像限流，其实是自 leak。

        ⚠️ **5xx 要退避重试。** 平台维护期间会连续吐 503，实测一轮 11 题
        全部撞死在 503 上——那不是评测结果，是平台故障，重试才是对的。
        """
        self.reap_orphans()
        payload = {"challenge_id": challenge_id, "competition_id": suite_for(challenge_id)}
        last = ""
        for i in range(attempts):
            r = self.s.post(f"{PLATFORM}/api/v1/instances", json=payload, timeout=120)
            if r.status_code < 400:
                return r.json()["id"]
            last = f"HTTP {r.status_code}: {r.text[:160]}"
            if r.status_code not in (429, 500, 502, 503, 504):
                r.raise_for_status()
            wait = min(60, 10 * (2**i))
            print(f"  [retry {i+1}/{attempts}] {last} → 等 {wait}s", flush=True)
            if r.status_code == 429:
                self.reap_orphans()
            time.sleep(wait)
        msg = f"启动实例失败（重试 {attempts} 次）：{last}"
        raise RuntimeError(msg)

    def reap_orphans(self) -> list[str]:
        """删掉所有本账号名下仍在运行的实例，返回被删的 id。

        批量评测是串行的，任何时刻都不该有第二个实例存活——所以"有实例"
        就等于"上一轮泄漏了"。清理是安全的，不会误删正在跑的题。
        """
        reaped: list[str] = []
        try:
            r = self.s.get(f"{PLATFORM}/api/v1/instances", timeout=40)
            if r.status_code != 200:
                return reaped
            data = json.loads(r.text, strict=False)
        except (requests.RequestException, json.JSONDecodeError):
            return reaped

        for inst in data.get("items", []):
            if inst.get("status") in {"ready", "starting"}:
                self.teardown(inst["id"])
                reaped.append(inst["id"])
        if reaped:
            print(f"  [reap] 清理残留实例 {len(reaped)} 个", flush=True)
            time.sleep(5)
        return reaped

    def wait_ready(self, iid: str, timeout: int = 180) -> str:
        """轮询到 ready，返回可访问的靶机 URL。

        Raises:
            TimeoutError: 到 ready 状态但地址不可用，或超时未就绪。

        ⚠️ 不能无条件取 ``services[0]``。``network_topology=engagement`` 的题
        只给 ``<challenge>.internal`` 这类私有 DNS 名——那需要 WireGuard 隧道
        才能解析，从评测机直连是 100% 失败。实测过：CTFARENA-052 就是这样，
        白烧了一整轮预算。所以这里必须校验地址形态，不可用就立刻抛错换题。
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = self.s.get(f"{PLATFORM}/api/v1/instances/{iid}/status", timeout=40)
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "ready":
                    services = (d.get("attack_surface") or {}).get("services") or []
                    for svc in services:
                        url = _public_url(svc)
                        if url:
                            return url
                    names = [s.get("host") for s in services]
                    msg = f"instance {iid} 无可直连地址（需要隧道？）services={names}"
                    raise TunnelRequiredError(msg)
            time.sleep(5)
        msg = f"instance {iid} not ready in {timeout}s"
        raise TimeoutError(msg)

    def probe_reachable(self, url: str, attempts: int = 3) -> tuple[bool, str]:
        """确认靶机真的能连上，而不只是平台说它 ready。

        ⚠️ 平台报 ready 不代表从评测机能访问。实测踩过：实例状态正常，
        但沙箱里的 ``curl`` 一直返回 ``000``（0.023 秒即失败，不是超时），
        agent 反复重试到耗完整道题的预算。加这一道探测，坏实例当场发现，
        不必先烧掉十几分钟。

        4xx/5xx 都算**可达**——题目本来就可能把根路径设成 404 或 403，
        那不是环境问题。只有连接层面的失败（DNS、拒绝、超时）才算不可达。

        Args:
            url: 靶机地址。
            attempts: 探测次数，容忍一次网络抖动。

        Returns:
            (是否可达, 说明)
        """
        last = ""
        for i in range(attempts):
            try:
                r = self.s.get(url, timeout=20, verify=False, allow_redirects=False)
                return True, f"HTTP {r.status_code}"
            except requests.RequestException as exc:
                last = f"{type(exc).__name__}: {str(exc)[:120]}"
                if i + 1 < attempts:
                    time.sleep(3)
        return False, last

    def submit(self, iid: str, flag: str) -> dict:
        r = self.s.post(
            f"{PLATFORM}/api/v1/submissions",
            json={"instance_id": iid, "question_id": "flag", "answer": flag},
            timeout=60,
        )
        return r.json()

    def teardown(self, iid: str) -> None:
        try:
            self.s.delete(f"{PLATFORM}/api/v1/instances/{iid}", timeout=90)
        except requests.RequestException:
            pass  # 删不掉不算错，TTL 会兜底


def _parse_guard(log: str) -> dict[str, object]:
    """从运行日志里抠出三个守卫的实际介入情况。

    守卫的价值全在"它有没有真的介入"。只写代码不观测，就会重演上一轮的
    错误：枚举守卫单测通过、真实日志重放通过，真实运行里却一次都没触发，
    而结果表上看不出区别。

    Args:
        log: `run_strix_ctf.py` 的完整标准输出。

    Returns:
        含 enum/journey/finish 三组计数的字典；日志缺失时给零值。
    """
    out: dict[str, object] = {
        "reach": 0,
        "enum_keys": 0,
        "enum_hits": log.count("ENUMERATION GUARD"),
        "journey_wall": 0,
        "journey_authed": False,
        "journey_created": False,
        "journey_payloads": 0,
        "journey_hits": log.count("USER JOURNEY GUARD"),
        "finish_refused": 0,
        "finish_hits": log.count("REFUSED: this summary"),
    }
    m = re.search(
        r"\[guard\] reach=(\d+) \(calls into guards\) \| enum keys=(\d+) "
        r"\| journey: wall=(\d+) authed=(\w+) created=(\w+) payloads=(\d+) "
        r"prompts=(\d+) \| finish: refused=(\d+)",
        log,
    )
    if m:
        out.update(
            reach=int(m.group(1)),
            enum_keys=int(m.group(2)),
            journey_wall=int(m.group(3)),
            journey_authed=m.group(4) == "True",
            journey_created=m.group(5) == "True",
            journey_payloads=int(m.group(6)),
            journey_prompts=int(m.group(7)),
            finish_refused=int(m.group(8)),
        )
        # reach=0 说明守卫一次都没被调用过——这一题的守卫数据全是废的，
        # 不能当成"行为良好"的证据。标出来，免得又被读成"今天没触发"。
        out["mount_broken"] = out["reach"] == 0
    return out


def _proxy_blackhole(target: str) -> dict[str, str]:
    """把"外网不可达"从"卡 60 秒"变成"立刻拒绝"。

    只做一件事：把 HTTP(S)_PROXY 指到一个关闭的本地端口，并用 NO_PROXY
    放行本题靶机与 LLM 网关。这样 agent 再想 `curl github.com/...` 会拿到
    瞬时 connection refused，而不是挂满超时——两者对模型的信息量完全不同。

    Args:
        target: 本题靶机地址（URL 或 host:port）。

    Returns:
        可直接并入子进程环境变量的字典。
    """
    from urllib.parse import urlsplit

    allowed: list[str] = ["localhost", "127.0.0.1", "::1"]
    host = urlsplit(target if "://" in target else f"//{target}").hostname
    if host:
        allowed.append(host)
    llm_host = urlsplit(os.environ.get("LLM_API_BASE", "")).hostname
    if llm_host:
        allowed.append(llm_host)
    allowed.extend(
        h.strip() for h in os.environ.get("CTF_NO_PROXY_EXTRA", "").split(",") if h.strip()
    )
    no_proxy = ",".join(dict.fromkeys(allowed))
    dead = "http://127.0.0.1:9"
    return {
        "HTTP_PROXY": dead,
        "HTTPS_PROXY": dead,
        "http_proxy": dead,
        "https_proxy": dead,
        "NO_PROXY": no_proxy,
        "no_proxy": no_proxy,
    }


def _new_run_id(cid: str) -> str:
    """生成一次运行的唯一名字。

    它同时充当沙箱目录名和 agent name。唯一性不是审美问题：strix 用
    ``strix_runs/<name>/.state/agents.db`` 认领 session，名字重复就等于
    "接着上一轮继续跑"。随机后缀用来兜住同一秒内的两次调用。
    """
    # 后缀要够宽：``token_hex(2)`` 只有 16 位，同秒内生成 200 个就有约 30%
    # 概率撞名（生日问题），撞名等于续跑。32 位把碰撞概率压到 1e-5 量级。
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{cid}-{secrets.token_hex(4)}"


def _fresh_box(name: str, root: str | Path = "/tmp/ctfbox") -> tuple[Path, Path]:
    """给一次运行准备**干净**的沙箱目录，返回 (box, log 路径)。

    必须是"删了重建"而不是"存在就复用"：复用会让上一轮的
    ``strix_runs/<name>/.state`` 留下来，strix 直接续跑同一个 agent
    （同一 agent id、同一份 /tmp 沙箱、同一段对话历史）。这种污染不报错，
    只表现为"今天状态特别好"，是最贵的一类假数据。

    只清本题目录，不动 ``/tmp/ctfbox`` 下的其他题——并发时误删别人正在
    跑的沙箱，会比污染更难查。

    Args:
        name: 运行名（唯一）。
        root: 沙箱根目录，测试时可换成临时目录。

    Returns:
        (沙箱目录, 日志文件路径)，目录已存在且为空。
    """
    box = Path(root) / name
    if box.exists():
        shutil.rmtree(box, ignore_errors=True)
    box.mkdir(parents=True, exist_ok=True)
    return box, box / "run.log"


def _git_commit(root: Path) -> str:
    """取当前提交号，写进结果行。

    没有它，一周后回看"这行 0.5 的通过率是哪版代码跑出来的"就无法回答，
    而对照实验的全部意义就在于能回答这个问题。取不到不报错——仓库被拷成
    tarball 时 git 可能不存在，这是正常情况，不是缺陷。
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    # VM 上是"本地写、远程跑"，项目目录不是 git 仓库，取不到 HEAD。
    # 退回到推送时写入的戳，否则这一列在真实运行里永远是 unknown——
    # 一个永远为空的字段比没有这个字段更糟，因为它看起来像在记录。
    try:
        stamp = root / ".codex-commit"
        if stamp.is_file():
            return stamp.read_text(encoding="utf-8").strip()[:12] or "unknown"
    except OSError:
        pass
    return "unknown"


def _archive_run(box: Path, name: str, dest_root: Path) -> Path:
    """把一题的取证材料整体拷到 ``dest_root/<name>/``。

    归档的三样东西缺一不可：``run.log``（工具流）、
    ``strix_runs/**/.state/agents.db``（完整 reasoning + 参数 + 输出）、
    以及跑它的提交号（由调用方写进结果行）。只留 log 的话，"模型当时
    为什么这么选"永远查不出来——009 的 12 次调用干了什么，就是靠 agents.db
    回放才看出来的。
    """
    dest = dest_root / name
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        shutil.copy2(box / "run.log", dest / "run.log")
    src_runs = box / "strix_runs"
    if src_runs.is_dir():
        shutil.copytree(src_runs, dest / "strix_runs", dirs_exist_ok=True)
    return dest


def run_agent(
    target: str,
    turns: int,
    timeout_s: int,
    name: str,
    extra: str = "",
    archive_dir: Path | None = None,
) -> tuple[str, float]:
    """跑一次 strix，返回 (完整日志, 墙钟耗时)。

    日志写文件而不是只在内存里：被强杀时还能从文件取证。

    **每题一个沙箱目录**（/tmp/ctfbox/<name>/）：这是本轮批测暴露出的最
    脏的问题——agent 会翻本机文件系统找 flag，翻到 /tmp/batch/*.log 里
    上一题的日志，或者 /workspace/ctf_recon.md 里冒烟测试的残留，就把
    别的题的 flag 当成自己的答案。比赛时同容器连打多题也会这样互相污染。
    cwd 同时决定 strix_runs 的位置（core/paths.py:14），所以把 cwd 移进
    沙箱目录，agent 就算 ls -R /tmp 也只会看到自己这一题的东西。
    项目代码用绝对路径引用，不受 cwd 变化影响。
    """
    root = Path(__file__).resolve().parent.parent
    goal = (root / "config" / "ctf_goal.txt").read_text(encoding="utf-8")
    instruction = f"{goal}\n\n{extra}" if extra else goal

    # 每次都是全新沙箱：见 `_fresh_box` 里关于 session resume 的记录。
    box, log = _fresh_box(name)

    env = {
        "PYTHONPATH": "src:vendor/src",
        # 外网黑洞：比赛规定 agent_internet=deny，但沙箱里 curl 一个外网域名
        # 会**挂 20-60 秒**才超时。009 复跑实测：agent 试了两次下载字典
        # （raw.githubusercontent.com），外加 3 次 write_stdin 等待，约 8 次
        # 调用 / 90 秒花在"已知不可能成功"的事上。
        # 指到一个必然拒绝的本地端口，失败就从"慢"变成"瞬时"，模型立刻换路。
        # ⚠️ NO_PROXY 必须放行两类：本题靶机（否则打不到目标）和 LLM 网关
        # （否则 strix 自己连不上模型，整题直接挂）。
        **_proxy_blackhole(target),
        "STRIX_RUNTIME_BACKEND": "local",
        "PYTHONUNBUFFERED": "1",
        # 凭据只来自环境。仓库里写死 key 的代价不是"泄漏"，而是几个月后
        # 它过期时表现为神秘 401，排查方向全错。
        "LLM_API_KEY": os.environ.get("LLM_API_KEY", ""),
        "LLM_API_BASE": os.environ.get("LLM_API_BASE", ""),
        "STRIX_LLM": os.environ.get("STRIX_LLM", ""),
        "STRIX_TELEMETRY": "false",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    cmd = [
        str(root / ".venv/bin/python"), "-u", str(root / "scripts/run_strix_ctf.py"),
        "--target", target, "--turns", str(turns), "--name", name,
        "--instruction", instruction,
    ]
    started = time.time()
    # PYTHONPATH 是相对路径，必须配合 cwd=root 才能 import 到 ctf_strix，
    # 而沙箱隔离又要求 cwd=box——改成绝对路径，cwd 就能放心交给 box。
    env["PYTHONPATH"] = f"{root / 'src'}:{root / 'vendor/src'}"

    # ⚠️ 不能用 subprocess.run(timeout=...)。它只杀直接子进程，而 strix 会
    # fork 出沙箱/工具子进程，孙进程变孤儿继续打靶机，墙钟形同虚设。
    # 实测：CTFARENA-018 预算 1248s，跑到 47 次工具调用仍未停。
    # 正确做法是 start_new_session 把整棵树放进新进程组，超时后按组杀。
    with log.open("w", encoding="utf-8") as fh:
        proc = subprocess.Popen(
            cmd, env=env, cwd=str(box),
            stdout=fh, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            fh.write(f"\n[WALLCLOCK TIMEOUT after {timeout_s}s]\n")
            fh.flush()
            _kill_group(proc)
    text = log.read_text(encoding="utf-8", errors="ignore")
    if archive_dir is not None:
        _archive_run(box, name, archive_dir)
    return text, time.time() - started


def _kill_group(proc: subprocess.Popen) -> None:
    """杀整个进程组，兜住孤儿孙进程。

    Args:
        proc: 以 ``start_new_session=True`` 启动的进程，其 pgid 等于自身 pid。
    """
    import signal

    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--plan", required=True, help="JSON 文件：题目计划")
    p.add_argument("--turns", type=int, default=25)
    p.add_argument("--wallclock", type=int, default=900, help="单题墙钟上限（秒）")
    p.add_argument("--out", default="/tmp/batch/results.jsonl")
    p.add_argument("--token", required=True)
    p.add_argument(
        "--archive-dir", default="~/runs",
        help="取证归档根目录（run.log + agents.db），默认 ~/runs",
    )
    p.add_argument(
        "--no-archive", action="store_true",
        help="不归档，只适合冒烟验证（会丢掉事后回放轨迹的能力）",
    )
    args = p.parse_args()

    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    archive = Path(args.archive_dir).expanduser()
    if not args.no_archive:
        archive.mkdir(parents=True, exist_ok=True)
    commit = _git_commit(Path(__file__).resolve().parent.parent)
    client = Client(args.token)

    # 按难度分层预算，但**上限要贴着实测值**，不能拍脑袋放大。
    #
    # 实测（平台验真的成功样本）：
    #   easy   : 11-82 次调用、163-728s
    #   medium : 18-51 次调用、174-358s
    #   hard   : 002=11 次/235s，016=10 次/380s，013=42 次/509s
    #
    # 上一版给 hard 开 96 轮 / 2870s（40×2.4 / 1248×2.3），是拿"010 轮次耗尽"
    # 当依据推出的。但后来 002/016 用 10-11 次就解出 hard，这个依据不成立——
    # **方向对了 25 轮就够，方向错了 96 轮也只是把失败成本放大 4 倍**。
    # 现在把 hard 收到 60/1800：够 013 那种要挖数据库的题用，又不会让跑偏的
    # 题烧满 48 分钟。
    tiers = {
        "easy": (args.turns, args.wallclock),
        "medium": (int(args.turns * 1.6), int(args.wallclock * 1.5)),
        "hard": (int(args.turns * 2.4), int(args.wallclock * 2.3)),
    }

    for idx, item in enumerate(plan, 1):
        cid, diff = item["id"], item["difficulty"]
        turns, wallclock = tiers.get(diff, (args.turns, args.wallclock))
        print(f"\n{'='*70}\n[{idx}/{len(plan)}] {cid} ({diff}) "
              f"budget: {turns} turns / {wallclock}s", flush=True)

        rec = {"idx": idx, "challenge": cid, "difficulty": diff, "started": time.time()}
        # 每次运行一个唯一名字。它同时是沙箱目录名和 agent name，所以
        # 唯一性直接等于"不会续跑"。随机后缀是防同一秒内的重复调用。
        run_id = _new_run_id(cid)
        rec["run_id"] = run_id
        rec["git_commit"] = commit
        iid = None
        try:
            t0 = time.time()
            iid = client.launch(cid)
            target = client.wait_ready(iid)
            rec["target"] = target
            rec["launch_s"] = round(time.time() - t0, 1)
            print(f"  ready in {rec['launch_s']}s -> {target}", flush=True)

            # 「ready」是平台对实例状态的说法，不是从这台机器能连上的证明。
            # 实测踩过：实例正常、沙箱 curl 全程 000，agent 把整道题的预算
            # 都花在重试上。坏实例要当场发现，不能让它先烧掉十几分钟。
            reachable, detail = client.probe_reachable(target)
            rec["reachable"] = reachable
            if not reachable:
                print(f"  ! 不可达（{detail}），换一个实例重试", flush=True)
                client.teardown(iid)
                iid = client.launch(cid)
                target = client.wait_ready(iid)
                rec["target"] = target
                reachable, detail = client.probe_reachable(target)
                rec["reachable"] = reachable
                if not reachable:
                    msg = f"两个实例都不可达: {detail}"
                    raise TimeoutError(msg)
                print(f"  重建后可达 -> {target}", flush=True)
            else:
                print(f"  可达 ({detail})", flush=True)

            rec["budget_turns"] = turns
            rec["budget_wall_s"] = wallclock
            log, wall = run_agent(
                target, turns, wallclock, run_id,
                archive_dir=None if args.no_archive else archive,
            )
            rec["agent_s"] = round(wall, 1)
            rec["tool_calls"] = log.count(" TOOL ")
            rec["turn_capped"] = "MaxTurnsExceeded" in log
            rec["wallclock_hit"] = "WALLCLOCK TIMEOUT" in log

            # 不能"排序取最后一个"，也不能只做不带靶机信息的启发式。
            # 实测踩过三种误判，全部由 flag_extract 处理：
            #   1. 跨题残留：agent 读到了上一题留下的 ctf_recon.md
            #   2. 模板占位符：prompt 里的 FLAG{...}
            #   3. 日志截断：flag 跨在 event_sink 截断边界上
            # 判据必须带本题靶机 host，否则分不清"这题的证据"和"别题的残留"。
            from ctf_strix.flag_extract import best_flag, fallback_flag, host_of

            # 守卫是否真的介入了，必须进数据。上一轮枚举守卫装在代码里、
            # 单测通过、真实日志重放也通过，但真实运行里一次都没触发——
            # 如果不记录，这种"装了等于没装"在结果表里完全看不出来。
            rec["guard"] = _parse_guard(log)

            own = host_of(target)
            flag = best_flag(log, own)
            # 主判据挑不出时，用"唯一候选"兜底。理由见 fallback_flag 的 docstring：
            # 009 复跑里 agent 真的解出来了，却因为 host 与 flag 隔着一个
            # heredoc 而被判无证据——**解出来不提交，比交错更亏**。
            rec["flag_confidence"] = "high" if flag else None
            if flag is None:
                flag = fallback_flag(log, own)
                if flag:
                    rec["flag_confidence"] = "low"
            rec["flags_found"] = [flag] if flag else []
            if flag:
                rec["flag_submitted"] = flag
                verdict = client.submit(iid, flag)
                rec["correct"] = bool(verdict.get("correct"))
                rec["solve_time_s"] = verdict.get("solve_time_s")
                rec["solve_rank"] = verdict.get("solve_rank")
            else:
                rec["correct"] = False
            print(f"  -> {'SOLVED' if rec['correct'] else 'FAILED'}  "
                  f"tools={rec['tool_calls']} agent={rec['agent_s']}s", flush=True)
        except TunnelRequiredError as exc:
            # 隧道类题跳过，不跑 agent。白跑一轮的代价是 13 分钟，而
            # 结果必然是失败——那不是数据，是噪音。
            rec["error"] = f"SKIPPED(需隧道): {exc}"
            rec["correct"] = False
            rec["skipped"] = True
            print(f"  -> SKIP 需隧道，跳过", flush=True)
        except Exception as exc:  # noqa: BLE001
            rec["error"] = f"{type(exc).__name__}: {exc}"
            rec["correct"] = False
            print(f"  -> ERROR {rec['error']}", flush=True)
        finally:
            if iid:
                client.teardown(iid)
            rec["total_s"] = round(time.time() - rec["started"], 1)
            with out.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
