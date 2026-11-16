"""Scope audit: the ledger says which hosts left the authorised set.

The run is handed one target URL.  Everything it then touches is either that
target, a host a *response* named (the app's own surface -- an internal API, a
sibling instance, a config dump's ``10.4.2.7``), or the model's own guess.
Only the third kind is a scope departure, and the ledger is the one place that
can tell them apart, because "what the app had already named" is only knowable
at record time.

This is an **audit**, not a gate: nothing here blocks a request.  The design
decision is deliberate -- a prompt that told the model a door was shut did not
change its behaviour (ledger §4.241), so the tool-side answer is to *record*
the departure where the model can see it, not to refuse it.

Negative cases matter as much as positive ones: a regex that flags ordinary
response text as a host would make every run look out of scope.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import prompt, traffic  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_ledger(monkeypatch):
    """Isolated ledger *and* a cleared authorised-target registry per test."""
    traffic.reset_authorized_targets()
    ledger = traffic.TrafficLedger(None)
    monkeypatch.setattr(traffic, "_LEDGER", ledger)
    yield ledger
    traffic.reset_authorized_targets()


def _ex(rid: str, url: str, body: str = "", headers: dict[str, str] | None = None):
    return traffic.Exchange(
        id=rid,
        ts=0.0,
        method="GET",
        url=url,
        status=200,
        resp_body=body,
        resp_headers=dict(headers or {}),
        size=len(body),
        elapsed=0.01,
    )


# ---------------------------------------------------------------- host parsing


def test_host_strips_scheme_port_and_userinfo():
    assert traffic._host("https://App.Example.TEST:8443/x?y=1") == "app.example.test"
    assert traffic._host("http://user:pw@app.example.test/") == "app.example.test"
    assert traffic._host("app.example.test/api") == ""


def test_hosts_in_finds_dns_names_and_bare_ipv4():
    """A config dump names the next service as a bare IP; missing it would make
    a *disclosed* host look like a guess."""
    found = traffic._hosts_in('{"api": "http://internal-pypi:8080", "db": "10.4.2.7"}')
    assert "internal-pypi" not in found  # single label, not a DNS name
    assert "10.4.2.7" in found


def test_hosts_in_ignores_ordinary_prose():
    """Negative case: prose without dotted tokens must not mint hosts."""
    found = traffic._hosts_in(
        "Upload the file, read the report, then retry with a longer payload."
    )
    assert found == set()


def test_filename_false_positives_are_accepted_on_purpose():
    """``server.py`` parses as a dotted name and *is* recorded.

    That is the safe direction: the cost is a filename the model would never
    dial being called "named by the app", while the opposite error -- a real
    internal host reported as a departure -- is what this audit exists to
    prevent.  A file-extension deny list would be a static blocklist tuned
    against one corpus, which is exactly what this module refuses to build.
    """
    assert "server.py" in traffic._hosts_in("cat server.py")


# ------------------------------------------------------------- classification


def test_task_host_is_target_and_registry_seeds_from_prompt_context():
    prompt._seed_scope({"authorized_targets": [{"type": "url", "value": "http://t.example.test:8080/"}]})
    assert traffic.authorized_hosts() == {"t.example.test"}

    traffic.record(request_id="r1", method="GET", url="http://t.example.test:8080/api")
    assert traffic.ledger().get("r1").scope == "target"


def test_first_contact_seeds_target_when_nothing_was_authorised(fresh_ledger):
    """An entrypoint that never seeds the registry must not mark the *first*
    host out of scope.  A second, unrelated host is still a departure: with no
    written target, first contact is the only anchor there is."""
    fresh_ledger.add(_ex("r1", "http://only.example.test/"))
    assert fresh_ledger.get("r1").scope == "target"
    fresh_ledger.add(_ex("r2", "http://elsewhere.example.test/"))
    assert fresh_ledger.get("r2").scope == "out_of_scope"


def test_host_named_by_a_prior_response_is_app_named():
    prompt._seed_scope({"authorized_targets": ["http://t.example.test"]})
    traffic.record(
        request_id="r1",
        method="GET",
        url="http://t.example.test/config",
        resp_body='{"registry": "http://internal-pypi.ctfy.run:8080"}',
    )
    traffic.record(request_id="r2", method="GET", url="http://internal-pypi.ctfy.run:8080/simple/")
    assert traffic.ledger().get("r2").scope == "app_named"


def test_bare_ip_from_a_body_counts_as_app_named():
    prompt._seed_scope({"authorized_targets": ["http://t.example.test"]})
    traffic.record(
        request_id="r1",
        method="GET",
        url="http://t.example.test/status",
        resp_body="upstream=none\npeer=10.4.2.7:5432\n",
    )
    traffic.record(request_id="r2", method="GET", url="http://10.4.2.7:5432/")
    assert traffic.ledger().get("r2").scope == "app_named"


def test_host_named_only_in_a_response_header_counts_as_app_named():
    prompt._seed_scope({"authorized_targets": ["http://t.example.test"]})
    traffic.record(
        request_id="r1",
        method="GET",
        url="http://t.example.test/",
        resp_headers={"Location": "http://sso.example.test/login"},
    )
    traffic.record(request_id="r2", method="GET", url="http://sso.example.test/login")
    assert traffic.ledger().get("r2").scope == "app_named"


def test_guessed_host_is_out_of_scope():
    prompt._seed_scope({"authorized_targets": ["http://t.example.test"]})
    traffic.record(request_id="r1", method="GET", url="http://t.example.test/")
    traffic.record(request_id="r2", method="GET", url="http://202.112.47.146:80/")
    assert traffic.ledger().get("r2").scope == "out_of_scope"


def test_a_response_cannot_retroactively_authorise_its_own_request():
    """Ordering guard: the host is learned *after* the request is classified."""
    prompt._seed_scope({"authorized_targets": ["http://t.example.test"]})
    traffic.record(
        request_id="r1",
        method="GET",
        url="http://guessed.example.test/",
        resp_body="see http://guessed.example.test/next",
    )
    assert traffic.ledger().get("r1").scope == "out_of_scope"


def test_url_without_host_is_unclassified():
    prompt._seed_scope({"authorized_targets": ["http://t.example.test"]})
    fresh = traffic.Exchange(id="r1", ts=0.0, method="GET", url="/api/notes")
    traffic.ledger().add(fresh)
    assert fresh.scope == ""


# ------------------------------------------------------------------ rendering


def test_traffic_list_reports_the_departure_and_marks_the_row():
    prompt._seed_scope({"authorized_targets": ["http://t.example.test"]})
    traffic.record(request_id="r1", method="GET", url="http://t.example.test/")
    traffic.record(request_id="r2", method="GET", url="http://202.112.47.146/")
    out = traffic.traffic_list()
    assert "out of scope (1): 202.112.47.146" in out
    assert " !r2" in out
    assert " !r1" not in out


def test_in_scope_rows_keep_the_historical_shape():
    """The marker must be invisible when nothing left scope."""
    prompt._seed_scope({"authorized_targets": ["http://t.example.test"]})
    traffic.record(request_id="r1", method="GET", url="http://t.example.test/api", status=200)
    out = traffic.traffic_list()
    assert "out of scope" not in out
    assert "  r1    GET" in out


def test_reset_clears_learned_and_seeded_hosts(fresh_ledger):
    fresh_ledger.add(_ex("r1", "http://seeded.example.test/", body="see http://named.other.test/"))
    fresh_ledger.reset()
    fresh_ledger.add(_ex("r1", "http://second.example.test/"))
    # A fresh ledger after reset seeds again rather than carrying the old set.
    assert fresh_ledger.get("r1").scope == "target"
    fresh_ledger.add(_ex("r2", "http://named.other.test/"))
    assert fresh_ledger.get("r2").scope == "out_of_scope"


def test_prompt_build_seeds_scope_even_on_the_override_path(tmp_path, monkeypatch):
    """The audit must describe the same run even when the prompt was replaced."""
    override = tmp_path / "prompt.txt"
    override.write_text("custom prompt", encoding="utf-8")
    monkeypatch.setenv("CTF_PROMPT_OVERRIDE", str(override))
    out = prompt.build({"authorized_targets": [{"type": "url", "value": "http://ov.example.test/"}]})
    assert out == "custom prompt"
    assert traffic.authorized_hosts() == {"ov.example.test"}