# 18 Path Variant Matrix (`path_variants`)

> Date: 2026-10-31. Motivation: the CTFARENA-095 failure was not knowledge, it
> was coverage. This document records the evidence, the design, and the
> rule check.

## 1. Evidence (from the transcript, not from guessing)

The DeepSeek arm on 095 spent **29 tool calls and 600s wall clock** and never
solved it. Reading `agents.db` message by message:

| Observation | Count |
|---|---|
| Calls re-testing one decoding hypothesis | 20+ |
| Calls trying all-uppercase spelling | **0** |
| Calls hitting a tool that no longer existed (`web_search`) | 2 |
| Calls investigating stale `/tmp/words.txt` from another run | 3 |

The GLM arm solved the same challenge in **8 calls / 72.2s**. The decisive
request was `/INTERNAL/banner` -- uppercase.

This is the same failure family as 007 (enumeration) and 009 (method sweep):
the model *can* do it, it just does not partition the hypothesis space. In
all three cases the fix that worked was **one call that sweeps the whole
dimension deterministically**, not another paragraph in the prompt.

## 2. Why six kinds and not one

Each kind corresponds to a *different* normalisation step that a real
middlebox either does or does not apply. They are independent, so trying only
one leaves the others untested:

| kind | variant of `/a/b` | what it tests |
|---|---|---|
| `upper` | `/A/B` | WAF rules are case-insensitive, router is not |
| `lower` | `/a/b` | the reverse (path was mixed case) |
| `title` | `/A/b` | only the first segment is normalised |
| `pct` | `/%61/%62` | proxy decodes once, backend sees encoded |
| `pct2` | `/%2561/%2562` | double decoding, the classic WAF bypass |
| `dot` | `/./a/./b` | proxy collapses dot segments, backend does not |
| `semi` | `/a;/b;` | servlet-style path params |
| `slash` | `//a//b` | duplicate-slash normalisation |
| `query` | `/a/b/?x=1` | query string confuses the route matcher |

`baseline=True` (default) also probes the original spelling, so a 2xx on a
variant can be distinguished from a catch-all route. Without the baseline the
result is uninterpretable.

## 3. Design decisions

- **Only GET by default.** Variant probing must not mutate target state; POST
  is available but opt-in. Same reasoning as `method_sweep` excluding DELETE.
- **Bounded.** At most 120 requests per call, concurrency 6. The target is one
  challenge box, not a load-test subject.
- **Percent-encoding keeps `/`.** `quote(s, safe="")` would collapse the whole
  path into one bogus segment, which tests nothing. Only the characters inside
  each segment are encoded.
- **Filtering.** 404/410 dropped; a variant whose status equals a failing
  baseline is dropped (it is the same rejection, not a bypass). This is what
  keeps the output short enough to be useful.
- **Verdict line.** The tool ends with one of three sentences: a real hit
  (with the reminder to check the baseline), a gate hit (401/403 means retry
  with auth), or "switch mechanism, stop adding variants". That last branch is
  the anti-095 guard: it tells the model to *stop* rather than iterate.

## 4. Rule check (competition constraints)

| Constraint | Status |
|---|---|
| One target vhost only | OK -- paths are joined to the caller-supplied `base_url` |
| No outbound internet | OK -- no external hosts, no wordlist downloads |
| Single instance | OK -- no extra process, just threads inside the agent |
| No destructive methods | OK -- GET default, DELETE not in the accepted set |
| No human hints | OK -- the tool is a mechanical sweep, the model still chooses inputs |
| Concurrency limits | 6 workers, 120 requests max per call |

The tool is a *deterministic expansion of an action the model already
performs manually*. It does not read challenge answers, does not know the flag,
and does not bypass the platform.

## 5. Registration

`capabilities.install_web_capabilities()` now installs three capabilities:
`http_probe`, `discovery`, `variants`. The failure of one does not skip the
others (pinned by `tests/test_capabilities.py`).

`enum_guard._PROBE_TOOLS` includes `path_variants`. Any new probe tool must be
added there too, otherwise the enumeration guard silently ignores it -- a
failure mode already documented in 4.19 (C-list).

## 6. Verification

- `tests/test_variants.py` -- 10 assertions, no network: variant generation,
  slash preservation, no-op rejection, argument validation.
- `tests/test_capabilities.py` -- parity across all three capabilities.
- Full suite: 226 passed locally (213 on the VM; the delta is host-only fixtures).

## 7. End-to-end validation (closed 2026-10-31, round 3)

Two runs, same code, same budget (25 turns / 420s), fresh instance each:

| model | 095 result | tools | agent wall | how the flag was found |
|---|---|---:|---:|---|
| DeepSeek | solved | 8 | 35.9s | `path_variants` -> `[upper] /INTERNAL/BANNER` 200 |
| GLM | solved | 13 | 74.0s | `path_variants` surfaced the variant, `http_probe` confirmed |

Both arms called the tool spontaneously, at the exact point where they used to
stall, and both stopped right after the hit. DeepSeek's provenance record in
`r5.jsonl` says `tool=path_variants` -- the first time in this project that a
flag came from the primitive instead of a hand-rolled curl loop.

The 095 split that motivated the tool is closed in the direction that matters:
**DeepSeek 0/2 -> 2/2 on 095**, with one of the two post-fix runs taking the
tool path. 074 stayed solved 2/2 before and after, so nothing regressed on
challenges that do not need a variant sweep.

Caveat: n=1 per cell in this round, and the two 095 runs are different
instances with different flags. The claim is "the tool gets selected and
produces the answer", not "it raises the solve rate by X".
