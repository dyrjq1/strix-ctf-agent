"""Step-0 measurement: is the source_leak gap "never found" or "found but unused"?

Read-only over the historical item streams (`agents.db`); zero tokens, no target.
For each run: which source/meta artifacts were requested, what the target
answered, and -- after a 2xx with real artifact content -- whether a later call
addressed something that was new in that body.  Three iterations were needed to
stop the parser from lying; each fix is a class of false positive worth keeping:

  v1  counted SPA catch-all pages as hits (every path 200, same size) and left
      shell output formats unparsed (`200 91 /path`, `path -> 404`, `404|169|`).
  v2  attributes a status to each probed path line-by-line and grades 2xx into:
        leak_content : body looks like the artifact (ref: refs/heads, "mappings",
                       openapi/paths, KEY=VALUE lines, robots rules, zip/sql)
        exists_200   : 2xx but no artifact body captured (curl -o /dev/null)
        spa_fallback : generic HTML / identical size across several paths
        blocked      : 401/403
        miss         : 404/410
        unknown      : no status found
  v3  dropped matches that are not requests at all: `process.env` / `x.map(`
      in code, prose params of save_threat_model/create_agent, foreign-host URLs
      in SSRF payloads, `file://` paths; status fallback now needs non-word
      delimiters so hashes like `d256b9...` are not read as HTTP 256.

Verdict this produced (docs/32 §9.3): 6 runs obtained real source content, all 6
converted; 239/397 never probed anything.  The gap is "not found", not "not used",
so S4 was cancelled.  Re-run on the VM: `python3 source_leak_gap.py`.
"""
import json
import re
import sqlite3
import sys
from pathlib import Path

ROOTS = [Path("/home/rjq/runs"), Path("/var/tmp/ctfbox")]

PATH_RES = {
    "dotgit": re.compile(r"(?<![\w])\.git(?:/[A-Za-z0-9_./\-]*)?\b", re.I),
    "dotmap": re.compile(r"/[A-Za-z0-9_./\-]*\.map\b|[A-Za-z0-9_-]+\.js\.map\b", re.I),
    "dotenv": re.compile(r"(?<![\w.])\.env\b|/[A-Za-z0-9_./\-]*/\.env\b", re.I),
    "swagger": re.compile(r"/[A-Za-z0-9_./\-]*(?:swagger|openapi)[A-Za-z0-9_./\-]*|(?:swagger|openapi)\.(?:json|yaml)", re.I),
    "robots": re.compile(r"/[A-Za-z0-9_./\-]*(?:robots\.txt|sitemap\.xml)", re.I),
    "backup": re.compile(r"/[A-Za-z0-9_./\-]*\.(?:bak|old|orig|swp|zip|tar|tgz|sql|rar|7z)\b", re.I),
    "hg_svn": re.compile(r"(?<![\w])\.(?:svn|hg)(?:/|\b)", re.I),
}
HTTP_ANCHOR = re.compile(r"https?://|\bcurl\b|\bwget\b|requests\.|httpx|urlopen|http\.client", re.I)
HTTP_TOOLS = {"http_probe", "method_sweep", "path_variants", "route_map", "traffic_view", "traffic_list"}

STRONG = {
    "dotgit": [re.compile(r"ref:\s*refs/", re.I), re.compile(r"repositoryformatversion", re.I),
               re.compile(r"\[core\]", re.I)],
    "dotmap": [re.compile(r'"mappings"'), re.compile(r"sourceMappingURL", re.I),
               re.compile(r'"sources"\s*:')],
    "dotenv": [re.compile(r"(?m)^[A-Z_][A-Z0-9_]{2,}=.+$")],
    "swagger": [re.compile(r'"(?:openapi|swagger)"\s*:'), re.compile(r'"paths"\s*:')],
    "robots": [re.compile(r"(?im)^\s*(?:user-agent|disallow|allow)\s*:", re.I)],
    "backup": [re.compile(r"PK\x03\x04"), re.compile(r"CREATE TABLE|INSERT INTO", re.I),
               re.compile(r"<\?php", re.I)],
    "hg_svn": [re.compile(r"ref:\s*refs/", re.I)],
}
ENV_LINE = re.compile(r"(?m)^[A-Z_][A-Z0-9_]{2,}=.+$")

LINE_STATUS = [
    re.compile(r"^(\d{3})\|"),
    re.compile(r"(?:^|\s)(\d{3})\s+\d+\s+/\S"),
    re.compile(r"->\s*(\d{3})\b"),
    re.compile(r"\[(\d{3})\]"),
    re.compile(r"HTTP/[\d.]+ (\d{3})"),
    re.compile(r"\bstatus(?:_code| code)?[^0-9]{0,6}(\d{3})", re.I),
    re.compile(r"\(\s*'[^']*'\s*,\s*(\d{3})\s*,"),
    re.compile(r"'[^']*'\s*,\s*(\d{3})\s*,"),
]
CALL_STATUS = [
    re.compile(r"\[HTTP (\d{3})\]"),
    re.compile(r"HTTP/[\d.]+ (\d{3})"),
]
TOKEN_RE = re.compile(r"/[A-Za-z0-9_][A-Za-z0-9_\-./]{4,}")


def parse_status_line(line):
    for rx in LINE_STATUS:
        m = rx.search(line)
        if m:
            return int(m.group(1))
    return None


def call_status(out):
    for rx in CALL_STATUS:
        m = rx.search(out)
        if m:
            return int(m.group(1)), True
    return None, False


def has_strong(fam, out):
    return any(rx.search(out) for rx in STRONG[fam])


def load_calls(db):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        items = con.execute("select message_data from agent_messages order by id").fetchall()
    finally:
        con.close()
    pending, calls = {}, []
    for (raw,) in items:
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "function_call":
            pending[obj.get("call_id")] = (obj.get("name") or "", obj.get("arguments") or "")
        elif obj.get("type") == "function_call_output":
            cid = obj.get("call_id")
            if cid not in pending:
                continue
            name, args = pending.pop(cid)
            out = obj.get("output")
            if not isinstance(out, str):
                out = json.dumps(out, ensure_ascii=False) if out is not None else ""
            calls.append((name, args, out))
    return calls


def in_foreign_url(args, start):
    window = args[max(0, start - 120):start]
    if "file://" in window:
        return True
    i = window.rfind("://")
    if i == -1:
        return False
    host = re.split(r"[/\s\"'`]", window[i + 3:])[0]
    return bool(host) and not host.endswith("ctfy.run")


def extract_paths(args):
    found = []
    for fam, rx in PATH_RES.items():
        for m in rx.finditer(args):
            p = m.group(0).strip("\"'`;,)")
            if len(p) >= 4 and not in_foreign_url(args, m.start()):
                found.append((fam, p))
    # dedupe by (fam, path)
    seen, out = set(), []
    for fam, p in found:
        k = (fam, p.lower())
        if k not in seen:
            seen.add(k)
            out.append((fam, p))
    return out


def classify_call(name, args, out):
    """Return list of (family, path, kind, status)."""
    if name not in HTTP_TOOLS:
        if name != "exec_command" or not HTTP_ANCHOR.search(args):
            return []
    paths = extract_paths(args)
    if not paths:
        return []
    cs, explicit = call_status(out)
    lines = out.splitlines()
    res = []
    for fam, p in paths:
        needle = p.lower() if "/" in p else p.lower()
        if len(needle) < 4:
            needle = p.lower()
        hit_line, st = None, None
        if True:
            for j, line in enumerate(lines):
                if not (needle and needle in line.lower()):
                    continue
                for k in (j, j + 1):
                    if k >= len(lines):
                        break
                    s = parse_status_line(lines[k])
                    if s is None:
                        m = re.search(r"(?<![\w.])([1-5]\d{2})(?![\w.])", lines[k])
                        s = int(m.group(1)) if m else None
                    if s is not None:
                        hit_line, st = lines[k], s
                        break
                if st is not None:
                    break
        if st is None:
            st = cs
        if st is None:
            kind = "unknown"
        elif 200 <= st < 300:
            if has_strong(fam, out):
                kind = "leak_content"
            else:
                body = out
                low = body.lower()
                generic = ("<!doctype html" in low or "<html" in low)
                sizes = re.findall(r"(?<![\w.])(\d{3})\s+(\d+)\s+text/html", out, re.I)
                catchall = len(sizes) >= 3 and len({s for _, s in sizes}) == 1
                if catchall or (generic and len(body) < 4000):
                    kind = "spa_fallback"
                else:
                    kind = "exists_200"
        elif st in (401, 403):
            kind = "blocked"
        elif st in (404, 410):
            kind = "miss"
        else:
            kind = "other"
        res.append((fam, p, kind, st, hit_line or ""))
    return res


RANK = {"leak_content": 5, "exists_200": 4, "blocked": 3, "other": 2,
        "spa_fallback": 1, "unknown": 0, "miss": -1}


def main():
    seen, run_dirs = set(), []
    for root in ROOTS:
        if not root.exists():
            continue
        for d in sorted(root.glob("2026*")):
            if d.is_dir() and d.name not in seen:
                seen.add(d.name)
                run_dirs.append(d)

    rows, skipped = [], 0
    for run_dir in run_dirs:
        dbs = list(run_dir.glob("strix_runs/*/.state/agents.db"))
        if not dbs:
            skipped += 1
            continue
        try:
            calls = load_calls(dbs[0])
        except Exception as e:  # noqa: BLE001
            skipped += 1
            print(f"ERR {run_dir.name}: {e}", file=sys.stderr)
            continue
        if len(calls) < 3:
            skipped += 1
            continue
        log_path = run_dir / "run.log"
        log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        all_out = "\n".join(c[2] for c in calls)
        solved = ("ACCEPTED:" in all_out) or bool(re.search(r"\bSOLVED\b", log_text))

        ev = []  # (idx, fam, path, kind, status, line)
        for i, (name, args, out) in enumerate(calls):
            for fam, p, kind, st, line in classify_call(name, args, out):
                ev.append((i, fam, p, kind, st, line))

        best = "none"
        if ev:
            best = max((e[3] for e in ev), key=lambda k: RANK.get(k, -2))

        converted, conv_kind = False, None
        leaks = [e for e in ev if e[3] == "leak_content"]
        if leaks:
            first_i, fam, path, _k, _s, _l = leaks[0]
            before = "\n".join(c[1] for c in calls[: first_i + 1]).lower()
            body = calls[first_i][2]
            new_tokens = {t for t in (x.lower() for x in TOKEN_RE.findall(body))
                          if len(t) >= 6 and t not in before}
            later = calls[first_i + 1:]
            for _n, args, _o in later:
                la = args.lower()
                if any(t in la for t in new_tokens):
                    converted, conv_kind = True, "new_token"
                    break
            if not converted:
                for _n, args, _o in later:
                    if path.lower() in args.lower() or (
                            len(path.split("/")[-1]) >= 5 and path.split("/")[-1].lower() in args.lower()):
                        converted, conv_kind = True, "refetch"
                        break

        if not converted:
            exs = [e for e in ev if e[3] == "exists_200"]
            if exs:
                i0, _f, p0 = exs[0][0], exs[0][1], exs[0][2]
                for _n, args, _o in calls[i0 + 1:]:
                    if p0.lower() in args.lower():
                        converted, conv_kind = True, "refetch"
                        break

        kinds = [e[3] for e in ev]
        rows.append({
            "run": run_dir.name,
            "calls": len(calls),
            "solved": solved,
            "probed": bool(ev),
            "best": best,
            "n_leak": kinds.count("leak_content"),
            "n_exists": kinds.count("exists_200"),
            "n_spa": kinds.count("spa_fallback"),
            "n_blocked": kinds.count("blocked"),
            "n_miss": kinds.count("miss"),
            "n_unknown": kinds.count("unknown"),
            "families": sorted({e[1] for e in ev}),
            "leak_families": sorted({e[1] for e in leaks}),
            "converted": converted,
            "conv_kind": conv_kind,
            "events": [{"i": e[0], "fam": e[1], "path": e[2][:90], "kind": e[3],
                        "status": e[4], "line": e[5][:120]} for e in ev[:12]],
        })

    print(f"runs analyzed={len(rows)} skipped={skipped} solved={sum(r['solved'] for r in rows)}")
    probed = [r for r in rows if r["probed"]]
    print(f"probed={len(probed)}  not-probed={len(rows) - len(probed)}")
    print("\nbest evidence per run:")
    for k in ("leak_content", "exists_200", "blocked", "other", "spa_fallback", "unknown", "miss"):
        rs = [r for r in probed if r["best"] == k]
        if rs:
            print(f"  {k:13} {len(rs):3}  solved {sum(r['solved'] for r in rs):2}")
    rs = [r for r in rows if not r["probed"]]
    print(f"  {'never probed':13} {len(rs):3}  solved {sum(r['solved'] for r in rs):2}")

    print("\nby family (any event of that family):")
    for fam in PATH_RES:
        rs = [r for r in probed if fam in r["families"]]
        if not rs:
            continue
        leak = sum(1 for r in rs if fam in r["leak_families"])
        miss = sum(1 for r in rs if any(e["fam"] == fam and e["kind"] == "miss" for e in r["events"]))
        print(f"  {fam:7} runs={len(rs):3} leak_content={leak:2} miss_runs={miss:3} "
              f"solved={sum(r['solved'] for r in rs):2}")

    leaks = [r for r in probed if r["n_leak"] > 0]
    conv = [r for r in leaks if r["converted"]]
    print(f"\nleak_content runs={len(leaks)}  converted={len(conv)}  "
          f"solved among converted={sum(r['solved'] for r in conv)}  "
          f"solved among not-converted={sum(r['solved'] for r in leaks if not r['converted'])}")
    if leaks:
        print("leak runs detail:")
        for r in leaks:
            print(f"  {r['run']:42} solved={int(r['solved'])} conv={int(r['converted'])}"
                  f"({r['conv_kind']}) fam={','.join(r['leak_families'])} calls={r['calls']}")

    print("\nexists_200 runs detail (2xx but no artifact body captured):")
    for r in probed:
        if r["best"] == "exists_200":
            print(f"  {r['run']:42} solved={int(r['solved'])} fam={','.join(r['families'])} "
                  f"calls={r['calls']} conv={int(r['converted'])}")

    strong = {"dotgit", "dotmap", "dotenv", "swagger", "backup", "hg_svn"}
    sl = [r for r in probed if set(r["leak_families"]) & strong]
    print(f"\nstrong-artifact leak runs (.git/.map/.env/swagger/backup)={len(sl)}  "
          f"converted={sum(1 for r in sl if r['converted'])}  "
          f"solved={sum(r['solved'] for r in sl)}")
    for r in sl:
        print(f"  {r['run']:42} fam={','.join(r['leak_families'])} conv={int(r['converted'])} "
              f"solved={int(r['solved'])}")

    out = Path("/home/rjq/source_leak_gap2.json")
    out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    print(f"\nrows -> {out}")


if __name__ == "__main__":
    main()