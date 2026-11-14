"""Startup model-endpoint probe (2026-11-14 outage).

The probe exists to turn "three lanes spent 66 minutes talking to a host that
was not there" into "three lanes exited in ten seconds with a reason".
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import httpx
import pytest

from ctf_strix import llm_preflight


ENV = {
    "LLM_API_BASE": "https://maas.example.com/compatible-mode/v1",
    "STRIX_LLM": "openai/deepseek-v4.1-flash-1017",
    "LLM_API_KEY": "sk-test-not-a-real-key",
}


@pytest.fixture(autouse=True)
def _no_ambient_env(monkeypatch):
    """Keep the developer's real endpoint out of every assertion."""
    for name in ("LLM_API_BASE", "OPENAI_API_BASE", "STRIX_LLM", "LLM_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def test_describe_is_none_without_an_endpoint():
    assert llm_preflight.describe({}) is None
    assert llm_preflight.describe({"LLM_API_BASE": "https://x/v1"}) is None
    assert llm_preflight.describe({"STRIX_LLM": "openai/m"}) is None


def test_describe_splits_provider_and_host():
    endpoint = llm_preflight.describe(ENV)

    assert endpoint is not None
    assert endpoint.model == "openai/deepseek-v4.1-flash-1017"
    assert endpoint.model_id == "deepseek-v4.1-flash-1017"
    assert endpoint.host == "maas.example.com"
    assert endpoint.key_present is True


def test_describe_records_the_provider():
    assert llm_preflight.describe(ENV).provider == "openai"
    assert llm_preflight.describe({"LLM_API_BASE": "https://x/v1", "STRIX_LLM": "glm-5.3"}).provider == "openai"
    assert (
        llm_preflight.describe({"LLM_API_BASE": "https://x", "STRIX_LLM": "anthropic/claude-x"}).provider
        == "anthropic"
    )


def test_probe_skips_a_provider_it_cannot_speak(monkeypatch):
    """anthropic/gemini 在 /chat/completions 上是 404，探针不能据此判死。"""

    def explode(*_args, **_kwargs):
        raise AssertionError("non-OpenAI provider must not be probed")

    monkeypatch.setattr(llm_preflight, "_post", explode)
    env = dict(ENV, STRIX_LLM="anthropic/claude-x")

    result = llm_preflight.probe(env=env)

    assert result.ok is True
    assert result.reason == "provider_unprobed"


def test_describe_marks_a_missing_key():
    env = dict(ENV)
    env.pop("LLM_API_KEY")

    endpoint = llm_preflight.describe(env)

    assert endpoint is not None
    assert endpoint.key_present is False


def test_describe_accepts_a_model_without_a_provider_prefix():
    env = {"LLM_API_BASE": "https://x/v1", "STRIX_LLM": "glm-5.3"}

    endpoint = llm_preflight.describe(env)

    assert endpoint is not None
    assert endpoint.model_id == "glm-5.3"


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        ("https://h/v1", "https://h/v1/chat/completions"),
        ("https://h/v1/", "https://h/v1/chat/completions"),
        ("https://h/v1/chat/completions", "https://h/v1/chat/completions"),
    ],
)
def test_chat_url_forms(base, expected):
    assert llm_preflight._chat_url(base) == expected


def test_enabled_ignores_pytest_current_test():
    """pytest 会把这个变量带进子进程；拿它当开关等于给冒烟测试留静默后门。"""
    env = dict(ENV, PYTEST_CURRENT_TEST="tests/test_x.py::test_y (call)")

    assert llm_preflight.enabled(env) is True


def test_enabled_can_be_forced_and_disabled():
    assert llm_preflight.enabled(dict(ENV, CTF_LLM_PREFLIGHT="1")) is True
    assert llm_preflight.enabled(dict(ENV, CTF_LLM_PREFLIGHT="0")) is False
    # Forcing it on still requires something to probe.
    assert llm_preflight.enabled({"CTF_LLM_PREFLIGHT": "1"}) is False


def test_probe_without_an_endpoint_passes():
    result = llm_preflight.probe(env={})

    assert result.ok is True
    assert result.reason == "not_configured"


def test_probe_without_a_key_fails_fast():
    env = dict(ENV)
    env.pop("LLM_API_KEY")

    result = llm_preflight.probe(env=env)

    assert result.ok is False
    assert result.reason == "no_key"
    # 死 key 换端点也救不了：口径必须是 credential，不是 unreachable。
    assert result.kind == "credential"


def test_probe_accepts_a_served_request(monkeypatch):
    body = '{"id":"x","choices":[{"message":{"content":"p"}}]}'
    monkeypatch.setattr(llm_preflight, "_post", lambda *a, **k: (200, body))

    result = llm_preflight.probe(env=ENV)

    assert result.ok is True
    assert result.reason == "ok"
    assert result.status == 200


def test_probe_rejects_a_dead_credential(monkeypatch):
    monkeypatch.setattr(llm_preflight, "_post", lambda *a, **k: (401, '{"error":"bad key"}'))

    result = llm_preflight.probe(env=ENV)

    assert result.ok is False
    assert result.reason == "http_401"
    assert result.kind == "credential"
    assert result.status == 401


def test_probe_treats_rate_limiting_as_reachable(monkeypatch):
    monkeypatch.setattr(llm_preflight, "_post", lambda *a, **k: (429, "slow down"))

    result = llm_preflight.probe(env=ENV)

    assert result.ok is True
    assert result.reason == "http_429"


def test_probe_passes_an_overloaded_gateway_through(monkeypatch):
    """5xx = 端点活着但过载（滚动发布约一分钟），该由重试梯子兜。"""
    monkeypatch.setattr(llm_preflight, "_post", lambda *a, **k: (503, "upstream down"))

    result = llm_preflight.probe(env=ENV)

    assert result.ok is True
    assert result.reason == "http_503"
    assert result.kind == "overloaded"


def test_probe_passes_a_slow_first_byte_through(monkeypatch):
    """排队高峰首字节 15-20s：慢不是死，真 run 有 300s 超时。"""

    def slow(*_args, **_kwargs):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(llm_preflight, "_post", slow)

    result = llm_preflight.probe(env=ENV, attempts=2)

    assert result.ok is True
    assert result.kind == "timeout_unproven"


def test_probe_flags_a_wrong_path(monkeypatch):
    monkeypatch.setattr(llm_preflight, "_post", lambda *a, **k: (404, "not found"))

    result = llm_preflight.probe(env=ENV)

    assert result.ok is False
    assert result.kind == "misconfigured"


def test_probe_passes_a_2xx_that_is_not_a_completion(monkeypatch):
    """ISP 劫持返回 200 HTML：放行但留痕，别把读不懂当成功。"""
    monkeypatch.setattr(llm_preflight, "_post", lambda *a, **k: (200, "<html>portal</html>"))

    result = llm_preflight.probe(env=ENV)

    assert result.ok is True
    assert result.reason == "http_2xx_nonjson"


def test_probe_reports_a_connection_failure(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise httpx.ConnectError("Connection error.")

    monkeypatch.setattr(llm_preflight, "_post", refuse)

    result = llm_preflight.probe(env=ENV, attempts=1)

    assert result.ok is False
    assert result.reason == "connect"
    assert result.kind == "unreachable"
    assert "Connection error" in result.detail


def test_probe_reports_a_resolution_failure(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise OSError("Name or service not known")

    monkeypatch.setattr(llm_preflight, "_post", refuse)

    result = llm_preflight.probe(env=ENV, attempts=1)

    assert result.ok is False
    assert result.reason == "dns"
    assert result.kind == "unreachable"


def test_probe_retries_a_transport_blip(monkeypatch):
    calls = {"n": 0}

    def flaky(*_args, **_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("Connection reset")
        return 200, "{}"

    monkeypatch.setattr(llm_preflight, "_post", flaky)
    monkeypatch.setattr(llm_preflight.time, "sleep", lambda *_a, **_k: None)

    result = llm_preflight.probe(env=ENV, attempts=2)

    assert result.ok is True
    assert calls["n"] == 2


def test_probe_does_not_retry_a_slow_blowover(monkeypatch):
    """DNS 黑洞一次 40 s（2026-11-14 实测）：第二次只是换个理由再等 40 s。"""
    calls = {"n": 0}
    ticks = iter([0.0, 40.0, 41.0, 81.0])

    def refuse(*_args, **_kwargs):
        calls["n"] += 1
        raise httpx.ConnectError("Temporary failure in name resolution")

    monkeypatch.setattr(llm_preflight, "_post", refuse)
    monkeypatch.setattr(llm_preflight.time, "monotonic", lambda: next(ticks, 81.0))

    result = llm_preflight.probe(env=ENV, attempts=2)

    assert result.ok is False
    assert calls["n"] == 1


def test_summary_and_dict_never_carry_the_key(monkeypatch):
    """provider 会在 401 正文里回显 key（'Incorrect API key provided: sk-...'）。"""
    echoed = '{"error":{"message":"Incorrect API key provided: sk-test-not-a-real-key"}}'
    monkeypatch.setattr(llm_preflight, "_post", lambda *a, **k: (401, echoed))

    result = llm_preflight.probe(env=ENV)

    assert "sk-test-not-a-real-key" not in result.summary()
    assert "sk-test-not-a-real-key" not in repr(result.as_dict())
    # 脱敏后仍留有诊断价值。
    assert "Incorrect API key" in result.detail


def test_gateway_session_credentials_are_redacted_too(monkeypatch):
    """网关会话凭据（pk_ 前缀，v1.0 参赛接口文档）同样会被 401 正文回显。

    echo 的 pk_ 与 ENV 里配置的 sk- 不同——只有兜底正则能拦住它，
    传给 ``_redact`` 的精确 key 替换帮不上忙。
    """
    echoed = '{"error":{"message":"Incorrect API key provided: pk_1a2b3c4d5e6f7g8h"}}'
    monkeypatch.setattr(llm_preflight, "_post", lambda *a, **k: (401, echoed))

    result = llm_preflight.probe(env=ENV)

    assert "pk_1a2b3c4d5e6f7g8h" not in result.summary()
    assert "pk_1a2b3c4d5e6f7g8h" not in repr(result.as_dict())
    assert "Incorrect API key" in result.detail


# ------------------------------------------------------------ 接线钉
# 预检只在进程启动时判一次生死，单测驱动不了；钉源码形状是当前最强的
# 验证——预检必须早于任何 guard 安装，失败走 exit 3（不与 agent 的
# exit 0/1/2 混淆），且「没配端点」「显式跳过」都不拦。
def _run_src() -> str:
    return (Path(__file__).resolve().parent.parent / "scripts" / "run_strix_ctf.py").read_text(
        encoding="utf-8"
    )


def test_harness_preflights_before_installing_any_guard():
    src = _run_src()

    preflight_pos = src.index("preflight = llm_preflight.guard()")
    assert preflight_pos < src.index("from ctf_strix.local_backend import install")
    assert preflight_pos < src.index("agent_mod._check_soft_timeout()")
    # 端点归属行先于判定，只打 model/host/key 三态，不打 key。
    assert src.index("[llm] endpoint model=") < preflight_pos
    tail = src[preflight_pos : src.index("from ctf_strix.local_backend import install")]
    assert "return llm_preflight.EXIT_CODE" in tail
    # 退出码必须与 batch_eval 的归因同源，否则日志里又变回 error。
    assert llm_preflight.EXIT_CODE == 3


def test_harness_result_out_defaults_to_none():
    """--result-out 缺省为空：老调用方行为不变，硬墙钟仍不落盘。"""
    parser_src = _run_src()
    block = parser_src[parser_src.index('"--result-out"') :]
    block = block[: block.index(")")]

    assert 'default=""' in block


def test_batch_eval_records_the_preflight_exit_as_its_own_reason():
    """rc=3 不能落进 error：那是「没跑起来」，不是「跑了没解出」。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import batch_eval

    log = "[llm] preflight ok=False reason=dns kind=unreachable\n[agent-exit] rc=3\n"
    assert batch_eval._stop_reason_of(log) == "llm_unreachable"
    # 别的非零退出码保持原判据。
    assert batch_eval._stop_reason_of("[agent-exit] rc=2\n") == "error"
    # 不可达不是「值得换策略重开」的证据，也不能被当成题目难。
    assert batch_eval._resample_allowed("llm_unreachable") is False


# ------------------------------------------------- agent 侧接线（不是源码形状）
def _prepare_agent(tmp_path, monkeypatch):
    import json

    task = {
        "run_mode": "instance",
        "challenge": {"id": "X", "name": "x", "description": ""},
        "questions": [{"id": "flag", "prompt": "p"}],
        "target_endpoints": [{"label": "web", "type": "http", "url": "http://127.0.0.1:9"}],
        "result": {"path": str(tmp_path / "result.json")},
    }
    (tmp_path / "task.json").write_text(json.dumps(task), encoding="utf-8")
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.setenv("CTFY_WALL_DEADLINE", "0")
    monkeypatch.delenv("CTFY_EVAL_DRY_RUN", raising=False)
    monkeypatch.delenv("CTFY_SOFT_DEADLINE", raising=False)


def _payload(tmp_path):
    import json

    return json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))


def test_agent_writes_a_preflight_failure_into_result_json(tmp_path, monkeypatch):
    from ctf_strix import agent

    _prepare_agent(tmp_path, monkeypatch)
    verdict = llm_preflight.ProbeResult(ok=False, reason="dns", kind="unreachable", detail="no resolver")
    monkeypatch.setattr(agent.llm_preflight, "guard", lambda *_a, **_k: verdict)

    assert agent.main() == 0
    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "llm_unreachable"
    # 结构化落盘：平台侧不解析 writeup 也能查到为什么没跑。
    assert payload["llm_preflight"]["reason"] == "dns"
    assert payload["llm_preflight"]["kind"] == "unreachable"


def test_agent_labels_a_dead_key_as_a_credential_failure(tmp_path, monkeypatch):
    from ctf_strix import agent

    _prepare_agent(tmp_path, monkeypatch)
    verdict = llm_preflight.ProbeResult(ok=False, reason="no_key", kind="credential")
    monkeypatch.setattr(agent.llm_preflight, "guard", lambda *_a, **_k: verdict)

    assert agent.main() == 0
    # 死 key 换端点也救不了，不能让外层按「换端点重派」反复派同一条死路。
    assert _payload(tmp_path)["stop_reason"] == "credential_failure"


def test_agent_does_not_mislabel_an_unrelated_crash(tmp_path, monkeypatch):
    """两次传输失败之后，一个与模型无关的异常仍然是 error。"""
    from ctf_strix import agent, error_policy

    _prepare_agent(tmp_path, monkeypatch)
    monkeypatch.setattr(agent.llm_preflight, "guard", lambda *_a, **_k: llm_preflight.ProbeResult(ok=True, reason="ok"))

    def boom(*_args, **_kwargs):
        error_policy.note_network_failure(now=0.0)
        error_policy.note_network_failure(now=100.0)  # 连击成立、断路器已开
        raise RuntimeError("sandbox assembly failed")

    monkeypatch.setattr(agent, "_run_agent", boom)
    error_policy.reset_breaker()

    assert agent.main() == 0
    assert _payload(tmp_path)["stop_reason"] == "error"


def test_agent_marks_a_mid_run_abandoned_endpoint(tmp_path, monkeypatch):
    """retry_policy 真的放弃了端点，才允许把这一轮记成 llm_unreachable。"""
    from ctf_strix import agent, error_policy

    _prepare_agent(tmp_path, monkeypatch)
    monkeypatch.setattr(agent.llm_preflight, "guard", lambda *_a, **_k: llm_preflight.ProbeResult(ok=True, reason="ok"))

    def dropped(*_args, **_kwargs):
        error_policy.note_unreachable()
        raise ConnectionError("Connection refused")

    monkeypatch.setattr(agent, "_run_agent", dropped)
    error_policy.reset_breaker()

    assert agent.main() == 0
    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "llm_unreachable"
    assert payload["llm_errors"][0]["reason"] == "endpoint_unreachable"


def test_harness_gate_uses_guard_not_probe():
    """两个入口都必须走 guard()——probe() 会绕过 enabled()，单测里开真 socket。"""
    for relative in ("scripts/run_strix_ctf.py", "src/ctf_strix/agent.py"):
        text = (Path(__file__).resolve().parent.parent / relative).read_text(encoding="utf-8")
        assert "llm_preflight.guard()" in text, relative
        assert "llm_preflight.probe(" not in text, relative


# ------------------------------------------------- 第二轮复核（Codex N0–N6）
def _script(name: str) -> str:
    return (Path(__file__).resolve().parent.parent / "scripts" / name).read_text(encoding="utf-8")


def test_the_lane_path_installs_the_retry_policy():
    """N0：lane 走 run_strix_ctf，不是 agent.main。不装这一行，断路器就是装饰。

    预检只覆盖「开局端点就死」；「跑到第 5 分钟才死」全靠 ``retry_policy``
    与 ``note_network_failure()``，而它们只在 ``error_policy.install()``
    之后存在。
    """
    src = _script("run_strix_ctf.py")

    # 行首锚定，不是子串包含：注释掉（``# _error_policy.install()``）或包进
    # ``if False:`` 都会失配，而纯子串钉子在这两种变异下仍是绿的（三轮实测）。
    call = "_error_policy.install()"
    line = next(
        (ln for ln in src.splitlines() if re.fullmatch(r"\w+ = " + re.escape(call), ln.strip())),
        None,
    )
    assert line is not None, "error_policy.install() must be a statement, not a substring"
    install_pos = src.index(line)
    assert install_pos < src.index("from strix.core.runner import run_strix_scan")
    # 必须在 local_backend 之后（strix 可导入），否则 install() 静默返回 False。
    assert src.index("from ctf_strix.local_backend import install") < install_pos
    # 安装结果要留痕，否则 lane 日志里看不出重试策略没装上。
    assert "retry policy installed=" in src


def test_batch_eval_actually_passes_result_out():
    """M1 的正确钉子：只测 ``default=""`` 等于在测「功能关闭」。"""
    src = _script("batch_eval.py")

    expected = '"--result-out", str(box / "result.json"),'
    line = next((ln for ln in src.splitlines() if expected in ln), None)
    assert line is not None
    # 行首锚定：注释掉这一行仍含子串，但已经不是 cmd 列表的一项。
    assert line.strip() == expected


def test_batch_eval_does_not_call_a_preflight_refusal_a_crash():
    """N3：rc=3 是「没跑起来」，不能再同时写一条 ``agent-exit:rc3``。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import batch_eval

    refused = "[llm] preflight ok=False reason=dns kind=unreachable\n[agent-exit] rc=3\n"
    assert batch_eval._crash_error(refused) is None
    # 光有退出码不够：将来任何以 3 退出的真崩溃必须还是崩溃。
    assert batch_eval._crash_error("[agent-exit] rc=3\n") == ("agent-exit:rc3", "")
    assert batch_eval._crash_error("[agent-exit] rc=2\n") == ("agent-exit:rc2", "")


def test_batch_eval_maps_the_preflight_kind_to_a_usable_reason():
    """N2：死 key / 错路径换个端点还是同一个答案，不能都记成 unreachable。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import batch_eval

    credential = "[llm] preflight ok=False reason=http_401 kind=credential\n[agent-exit] rc=3\n"
    misconfigured = "[llm] preflight ok=False reason=http_404 kind=misconfigured\n[agent-exit] rc=3\n"
    dns = "[llm] preflight ok=False reason=dns kind=unreachable\n[agent-exit] rc=3\n"

    assert batch_eval._stop_reason_of(credential) == "credential_failure"
    assert batch_eval._stop_reason_of(misconfigured) == "misconfigured"
    assert batch_eval._stop_reason_of(dns) == "llm_unreachable"
    # 认不出 kind（日志被截断）时不要猜一个方向：猜错会让死 key 被当成主机不在。
    truncated = "[llm] preflight ok=False reason=http_401 kind=creden\n[agent-exit] rc=3\n"
    assert batch_eval._stop_reason_of(truncated) == "preflight_refused"
    # 没有预检行的 rc=3 是普通崩溃。
    assert batch_eval._stop_reason_of("[agent-exit] rc=3\n") == "error"
    # 四种都不值得换策略重开。
    for reason in (
        "credential_failure",
        "misconfigured",
        "llm_unreachable",
        "preflight_refused",
    ):
        assert batch_eval._resample_allowed(reason) is False


def test_an_anthropic_auth_token_counts_as_a_key(monkeypatch):
    """N4：桥接认的名字，探针也必须认，否则假判 no_key 拒掉一个能跑的 run。"""
    env = {
        "LLM_API_BASE": "https://maas.example.com/v1",
        "STRIX_LLM": "anthropic/claude-x",
        "ANTHROPIC_AUTH_TOKEN": "tok-not-a-real-key",
    }

    endpoint = llm_preflight.describe(env)

    assert endpoint is not None
    assert endpoint.key_present is True


def test_agent_does_not_relabel_a_later_crash_after_the_flag_was_armed(tmp_path, monkeypatch):
    """N1：旗标是一次性的，但消费时还必须看异常本身。

    子 agent 的传输失败会被 vendor 吞掉（不抛给 root），旗标留在原地；
    400 s 后一个与模型无关的崩溃撞上来，不能被记成断网。
    """
    from ctf_strix import agent, error_policy

    _prepare_agent(tmp_path, monkeypatch)
    monkeypatch.setattr(agent.llm_preflight, "guard", lambda *_a, **_k: llm_preflight.ProbeResult(ok=True, reason="ok"))

    def late_crash(*_args, **_kwargs):
        error_policy.note_unreachable()
        raise RuntimeError("sandbox assembly failed")

    monkeypatch.setattr(agent, "_run_agent", late_crash)
    error_policy.reset_breaker()

    assert agent.main() == 0
    payload = _payload(tmp_path)
    assert payload["stop_reason"] == "error"
    assert not payload.get("llm_errors")