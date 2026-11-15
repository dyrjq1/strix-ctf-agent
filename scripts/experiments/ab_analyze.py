"""Score the S2 A/B against the criterion that was written before it ran.

docs/32 §9: "failed-run call median down >= 15%, and solved count not below the
control arm".  Lowering the bar after seeing the numbers would be the exact
thing §7.3 forbids, so this prints the criterion first and the data second.
"""
import json
import pathlib
import statistics as st

ARMS = {"control": "/home/rjq/ab_control.jsonl", "shape": "/home/rjq/ab_shape.jsonl"}


def load(path):
    out = {}
    file = pathlib.Path(path)
    if not file.exists():
        return out
    for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except Exception:
            continue
        out[str(record.get("challenge"))] = record
    return out


data = {arm: load(path) for arm, path in ARMS.items()}
print("rows:", {arm: len(rows) for arm, rows in data.items()})

plan = {item["id"]: item for item in json.loads(pathlib.Path("/home/rjq/ab_plan.json").read_text())}
failing = [cid for cid, item in plan.items() if item["arm"] == "failing"]

both = [cid for cid in plan if cid in data["control"] and cid in data["shape"]]
print(f"paired questions: {len(both)}")
if not both:
    print("\nNo paired questions yet -- the run is still in flight, nothing to score.")
    raise SystemExit(0)

print(f"\n{'challenge':14} {'hist':7} {'ctl':>5} {'ctl_calls':>9} {'shp':>5} {'shp_calls':>9} "
      f"{'ctl_s':>7} {'shp_s':>7} {'stall':>6} {'hint':>5}")
for challenge in sorted(both, key=lambda c: (plan[c]["arm"], c)):
    ctl = data["control"][challenge]
    shp = data["shape"][challenge]
    guard = shp.get("guard") or {}
    print(
        f"{challenge:14} {plan[challenge]['arm']:7} "
        f"{str(bool(ctl.get('correct'))):>5} {ctl.get('tool_calls', 0):>9} "
        f"{str(bool(shp.get('correct'))):>5} {shp.get('tool_calls', 0):>9} "
        f"{ctl.get('agent_s', 0):>7.0f} {shp.get('agent_s', 0):>7.0f} "
        f"{guard.get('stall_max', guard.get('max_stall', '?'))!s:>6} "
        f"{guard.get('stall_hits', '?')!s:>5}"
    )

print()
for arm in ("control", "shape"):
    rows = [data[arm][c] for c in both]
    solves = sum(1 for r in rows if r.get("correct"))
    calls = [r.get("tool_calls", 0) for r in rows]
    print(f"{arm:8} solves {solves}/{len(rows)}  calls p50={st.median(calls):.0f} "
          f"mean={st.mean(calls):.1f} total={sum(calls)}")

# criterion 1: calls on questions that failed in *both* arms
both_failed = [
    c for c in both if not data["control"][c].get("correct") and not data["shape"][c].get("correct")
]
if both_failed:
    ctl_calls = [data["control"][c].get("tool_calls", 0) for c in both_failed]
    shp_calls = [data["shape"][c].get("tool_calls", 0) for c in both_failed]
    delta = st.median(shp_calls) - st.median(ctl_calls)
    pct = 100 * delta / st.median(ctl_calls) if st.median(ctl_calls) else 0
    print(f"\nfailed in both arms: n={len(both_failed)}  "
          f"median calls control={st.median(ctl_calls):.0f} shape={st.median(shp_calls):.0f} "
          f"({pct:+.0f}%)  -> criterion >=15% drop: {'PASS' if pct <= -15 else 'FAIL'}")

# criterion 2: solves must not drop
ctl_solves = sum(1 for c in both if data["control"][c].get("correct"))
shp_solves = sum(1 for c in both if data["shape"][c].get("correct"))
print(f"solves: control={ctl_solves} shape={shp_solves} -> "
      f"{'PASS' if shp_solves >= ctl_solves else 'FAIL'}")

# did the treatment actually fire?
hints = sum(1 for c in both if (data["shape"][c].get("guard") or {}).get("stall_hits", 0))
print(f"shape arm runs with >=1 stall hint: {hints}/{len(both)}")