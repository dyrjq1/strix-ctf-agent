"""Deterministic context v1: capture-time classes, obs store, fact ledger.

The contracts locked here are the ones that keep prefix caching and fact
integrity intact:

* a rewritten history is a fixed point (``f(f(x)) == f(x)``);
* request N's item bytes are a strict prefix of request N+1's;
* fact lines never vanish from a degraded output;
* observation stores are per-run and absent when ``CTFY_WORK_DIR`` is unset;
* readback cuts on meaning (function boundary / hit +-N), not a fixed window;
* ``CTF_OBS_OFF=1`` is byte-identical to the pre-change content cap.

Every sample string below is synthetic: no challenge id, IP or real flag.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import context as ctx_mod  # noqa: E402
from ctf_strix import fact_ledger, obs_store  # noqa: E402

#: Synthetic shapes only; the value has no meaning outside this fixture.
SYNTH_FLAG = "FLAG{synthetic_demo_value}"
SYNTH_TOKEN = "sess_abc123def456"


def _pair(call_id: str, output: str, name: str = "exec_command") -> list[dict]:
    return [
        {"type": "function_call", "call_id": call_id, "name": name, "arguments": "{}"},
        {"type": "function_call_output", "call_id": call_id, "output": output},
    ]


def _filler(lines: int, tag: str = "filler") -> str:
    return "\n".join(f"{tag}-{index:03d} " + ("x" * 32) for index in range(lines))


def _big_fact_output(token: str = SYNTH_TOKEN, flag: str = SYNTH_FLAG) -> str:
    body = _filler(70, "before")
    body += f"\nflag-line: {flag}\ncredential-line: session_id={token}\n"
    body += _filler(70, "after")
    return body


def _capper(**kwargs) -> ctx_mod.HistoryCapper:
    params = {"cap_chars": 2_000, "head": 1_200, "tail": 600, "arg_cap": 0}
    params.update(kwargs)
    return ctx_mod.HistoryCapper(**params)


def _serialise(items: list[dict]) -> str:
    return "\n".join(
        json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for item in items
    )


@pytest.fixture(autouse=True)
def _clean_state():
    fact_ledger.reset()
    obs_store.clear_cache()
    obs_store.set_run_token("testrunfixture")
    yield
    fact_ledger.reset()
    obs_store.clear_cache()


@pytest.fixture
def v1(tmp_path, monkeypatch):
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    monkeypatch.delenv("CTF_OBS_OFF", raising=False)
    obs_store.reset_for_tests()
    fact_ledger.reset()
    return tmp_path


# ------------------------------------------------------------------ a


def test_rewrite_is_byte_idempotent(v1):
    capper = _capper()
    items = _pair("c1", _big_fact_output())

    once, saved_once = capper.apply(items)
    twice, saved_twice = capper.apply(once)

    assert saved_once != 0
    assert saved_twice == 0
    assert twice == once
    # The degraded item is a stub, not the original; the fact block follows it.
    assert ctx_mod._ELISION_MARK in once[1]["output"]
    assert fact_ledger.is_virtual(once[2])


def test_stub_item_alone_passes_through(v1):
    capper = _capper()
    once, _ = capper.apply(_pair("c1", _big_fact_output()))
    anchored = [once[0], once[1]]

    out, saved = capper.apply(anchored)

    assert saved == 0
    assert out == anchored


# ------------------------------------------------------------------ b


def test_request_n_is_a_strict_prefix_of_request_n_plus_one(v1):
    raw: list[dict] = []
    previous = ""
    for turn in range(1, 4):
        token = f"{SYNTH_TOKEN}{turn}"
        raw += _pair(f"c{turn}", _big_fact_output(token=token))
        out, _ = _capper().apply(list(raw))
        current = _serialise(out)
        if previous:
            assert current.startswith(previous), f"prefix drifted at turn {turn}"
            assert len(current) > len(previous)
        previous = current
        # one virtual fact block after every function_call_output
        assert sum(1 for item in out if fact_ledger.is_virtual(item)) == turn


# ------------------------------------------------------------------ c


def test_fact_lines_survive_degradation_and_no_hit_means_no_fact(v1):
    capper = _capper()
    out, _ = capper.apply(_pair("c1", _big_fact_output()))

    stub = out[1]["output"]
    assert SYNTH_FLAG in stub
    assert f"session_id={SYNTH_TOKEN}" in stub
    assert "before-069" in stub  # line directly above the flag
    assert "after-000" in stub  # line directly below the credential
    assert [fact.rule for fact in fact_ledger.facts_for(ctx_mod._text_hash(_big_fact_output()))] == [
        "flag",
        "credential",
    ]

    before = fact_ledger.count()
    plain = _filler(180, "plain")
    plain_out, _ = capper.apply(_pair("c2", plain))
    assert len(plain_out) == 2
    assert not any(fact_ledger.is_virtual(item) for item in plain_out)
    assert fact_ledger.count() == before


# ------------------------------------------------------------------ d


def test_two_run_tokens_cannot_see_each_other(v1):
    obs_store.set_run_token("runalpha")
    alpha = obs_store.offload("alpha output", tool_name="exec_command", cls="process")
    obs_store.set_run_token("runbeta")
    beta = obs_store.offload("beta output", tool_name="exec_command", cls="process")

    assert alpha is not None and beta is not None
    assert alpha["id"] != beta["id"]
    assert [row["id"] for row in obs_store.entries()] == [beta["id"]]
    assert "beta output" not in obs_store.obs_list()
    assert obs_store.obs_view(alpha["id"]).startswith(f"[obs] no entry {alpha['id']!r}")


def test_unset_work_dir_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("CTFY_WORK_DIR", raising=False)
    monkeypatch.delenv("CTF_OBS_OFF", raising=False)

    assert obs_store.base_dir() is None
    assert obs_store.offload("never stored", cls="process") is None
    assert not any(tmp_path.rglob("obs.jsonl"))


# ------------------------------------------------------------------ e


def test_obs_view_uses_function_boundaries_not_a_fixed_window(v1):
    alpha_body = "\n".join(f"    alpha_step_{i} = {i}" for i in range(35))
    beta_body = "\n".join(f"    beta_step_{i} = {i}" for i in range(35))
    code = (
        "def alpha(input_value):\n"
        f"{alpha_body}\n"
        "    return input_value + 1\n"
        "\n"
        "def beta(input_value):\n"
        f"{beta_body}\n"
        "    return input_value + 2\n"
    )
    entry = obs_store.offload(code, tool_name="exec_command", cls="summary", hit_lines=[])
    assert entry is not None

    view = obs_store.obs_view(entry["id"], sel="block", arg="alpha")

    assert "def alpha" in view
    assert "alpha_step_0" in view
    assert "alpha_step_34" in view
    assert "return input_value + 1" in view
    assert "def beta" not in view


def test_obs_view_hits_returns_whole_hit_context(v1):
    lines = [f"row-{i:03d} " + ("y" * 24) for i in range(80)]
    lines[39] = f"row-039 session_id={SYNTH_TOKEN}"
    text = "\n".join(lines)
    entry = obs_store.offload(
        text, tool_name="exec_command", cls="fact", hit_lines=obs_store.fact_hit_lines(text)
    )
    assert entry is not None

    view = obs_store.obs_view(entry["id"], sel="hits", context=2)

    assert f"session_id={SYNTH_TOKEN}" in view
    assert "row-037" in view and "row-041" in view
    assert "row-001" not in view  # not a fixed window from the top


# ------------------------------------------------------------------ f


def test_ctf_obs_off_is_byte_identical_to_prechange_cap(v1, monkeypatch):
    monkeypatch.setenv("CTF_OBS_OFF", "1")
    text = _big_fact_output()

    out, saved = _capper().apply(_pair("c1", text))

    expected = ctx_mod._cap_text(
        text, limit=2_000, head=1_200, tail=600, evidence=True
    )
    assert saved != 0
    assert len(out) == 2
    assert out[1]["output"] == expected
    assert fact_ledger.count() == 0
    assert obs_store.entries() == []


# ------------------------------------------------------------------ g


def test_classifier_recognises_shapes_not_sample_values(v1):
    first = "def first_name(value):\n    return value\n"
    second = "def entirely_different(item):\n    return item\n"
    assert obs_store.classify(first)[0] == "summary"
    assert obs_store.classify(second)[0] == "summary"

    one = obs_store.classify(f"a: CTF{{one_shape}}\n")[0]
    two = obs_store.classify(f"b: CTF{{another_shape}}\n")[0]
    assert one == two == "fact"

    for pattern in (
        obs_store._DISASM_FUNC_RE,
        obs_store._PY_FUNC_RE,
        obs_store._CLASS_RE,
        obs_store._JS_FUNC_RE,
    ):
        assert not re.search(r"\d{1,3}(?:\.\d{1,3}){3}", pattern.pattern)

    for sample in (SYNTH_FLAG, SYNTH_TOKEN, _big_fact_output()):
        assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", sample)
        assert "CHAL-" not in sample
