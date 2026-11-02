"""Measure the fixed cost of spawning one child agent, from a run log.

Why this exists
---------------
``CTF_ALLOW_SUBAGENTS`` is off by default because coordination ate ~22% of the
turn budget on CTFARENA-009 (17 of 77 calls).  That number is quoted in
``tool_trim.py`` and ``docs/10``, but there was no script that reproduces it
from a single trace -- so nobody can tell whether a later run got better or
worse, or whether a given challenge shape can afford a child at all.

The judgement this supports: **can this challenge afford a child?**  A child is
worth spawning only when its coordination cost is a small share of the turn
budget.  What counts as "coordination" is fixed below and is not re-defined
per run -- otherwise every report would pick the framing that flatters its own
number.

What is counted
---------------
Coordination calls exist *only because* a child exists:

* ``create_agent`` / ``stop_agent`` / ``send_message_to_agent``
* ``wait_for_agents``
* ``view_agent_graph``

Calls that touch the challenge (``exec_command`` and friends) are **work** and
are counted separately, whoever made them.  A child that finishes in 5 calls is
a win even though 2 of the parent's calls were coordination.

Four costs are reported because they answer different questions:

``coordination_calls``
    Parent-side overhead.  Paid regardless of how good the child is.
``root_calls_before_spawn``
    How many turns the root burned before deciding to delegate.
``spawn_task_chars``
    Size of the task prompt the parent must write for the child.
``report_back_chars``
    Size of the completion message that lands back in the parent context.

The last two are token costs that a call count cannot see.

What is NOT measurable from a log
---------------------------------
``inherit_context=True`` copies the parent's whole input history into the
child, so the child pays that prefix on *every* request.  The log records the
spawn call, not the copied history, so this script reports it as ``unmeasured``
rather than pretending to know.  Measure it with
``context.HistoryCapper.last_request_chars`` on a live run.

Usage
-----
    python scripts/measure_swarm.py reports/SAMPLE-006.log
    python scripts/measure_swarm.py reports/*.log --json out.json

Exits 0 even when nothing is found: a log with no child is a valid data point
("this run paid no coordination"), not an error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

#: Tools that exist only because a child agent exists.
COORD_TOOLS = frozenset(
    {
        "create_agent",
        "stop_agent",
        "send_message_to_agent",
        "wait_for_agents",
        "view_agent_graph",
    }
)

#: Tools that touch the challenge (or prepare to).
WORK_TOOLS = frozenset(
    {
        "exec_command",
        "write_stdin",
        "http_probe",
        "route_map",
        "method_sweep",
        "path_variants",
        "file_triage",
        "apply_patch",
        "read_file",
        "write_file",
        "load_skill",
        "think",
        "finish_scan",
    }
)

#: ``  [adc2d0d6] TOOL create_agent {...}``
_TOOL_RE = re.compile(r"\[([0-9a-f]{6,})\] TOOL (\w+)(?: (.*))?$")
#: ``  [adc2d0d6] OUT  {json}``
_CHILD_ID_RE = re.compile(r'"agent_id":\s*"([0-9a-f]+)"')
_PARENT_ID_RE = re.compile(r'"parent_id":\s*"([0-9a-f]+)"')

#: One tool argument blob is one physical log line; the cap only guards against
#: a pathological line, we never need the whole prompt.
_MAX_ARG_CHARS = 200_000


def parse_log(path: Path) -> dict:
    """Split one run log into an agent graph and per-agent call sequences.

    Args:
        path: A strix run log, as written by ``scripts/batch_eval.py``.

    Returns:
        ``{"agents": {id: {"calls": [...], "coord": n, "work": n}},
        "order": [(agent_id, tool)], "parents": {child: parent},
        "spawn_task_chars": {parent: n}, "report_back_chars": n}``.
    """
    agents: dict[str, dict] = {}
    order: list[tuple[str, str]] = []
    parents: dict[str, str] = {}
    spawn_task_chars: dict[str, int] = {}
    report_back_chars = 0
    pending_spawn: str | None = None

    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")

            tool_m = _TOOL_RE.search(line)
            if tool_m:
                agent, tool, argtext = (
                    tool_m.group(1),
                    tool_m.group(2),
                    tool_m.group(3) or "",
                )
                entry = agents.setdefault(agent, {"calls": [], "coord": 0, "work": 0})
                entry["calls"].append(tool)
                order.append((agent, tool))
                if tool in COORD_TOOLS:
                    entry["coord"] += 1
                elif tool in WORK_TOOLS:
                    entry["work"] += 1

                if tool == "create_agent":
                    pending_spawn = agent
                    try:
                        blob = json.loads(argtext[:_MAX_ARG_CHARS])
                    except (json.JSONDecodeError, ValueError):
                        blob = None
                    if isinstance(blob, dict):
                        size = len(str(blob.get("task") or ""))
                        spawn_task_chars[agent] = spawn_task_chars.get(agent, 0) + size
                else:
                    pending_spawn = None
                continue

            # The child's ids come back on the OUT line of create_agent.
            if pending_spawn and '"agent_id"' in line:
                child = _CHILD_ID_RE.search(line)
                parent = _PARENT_ID_RE.search(line)
                if child:
                    parents[child.group(1)] = parent.group(1) if parent else pending_spawn
                pending_spawn = None
                continue

            # A completion report lands in the parent's context via
            # wait_for_agents; its size is a real token cost.
            if '"wait_outcome"' in line and '"messages"' in line:
                report_back_chars = max(report_back_chars, len(line))

    return {
        "agents": agents,
        "order": order,
        "parents": parents,
        "spawn_task_chars": spawn_task_chars,
        "report_back_chars": report_back_chars,
    }


def measure(path: Path) -> dict:
    """Summarise the coordination cost of one run.

    Args:
        path: Run log.

    Returns:
        A dict matching the module docstring, plus ``verdict``.
    """
    parsed = parse_log(path)
    agents = parsed["agents"]
    if not agents:
        return {"log": path.name, "ok": False, "reason": "no tool calls parsed"}

    total_calls = sum(len(a["calls"]) for a in agents.values())
    total_coord = sum(a["coord"] for a in agents.values())
    children = parsed["parents"]
    roots = [a for a in agents if a not in children]
    root = roots[0] if roots else None

    # Turns the root spent on its own before delegating.
    root_calls_before_spawn = None
    if children:
        seen = 0
        for agent, tool in parsed["order"]:
            if agent == root and tool in COORD_TOOLS:
                root_calls_before_spawn = seen
                break
            if agent == root:
                seen += 1

    child_work = sum(agents[c]["work"] for c in children if c in agents)
    share = (total_coord / total_calls) if total_calls else 0.0

    return {
        "log": path.name,
        "ok": True,
        "agents": len(agents),
        "children": len(children),
        "root": root,
        "total_calls": total_calls,
        "coordination_calls": total_coord,
        "coordination_share": round(share, 4),
        "root_calls_before_spawn": root_calls_before_spawn,
        "child_work_calls": child_work,
        "spawn_task_chars": sum(parsed["spawn_task_chars"].values()),
        "report_back_chars": parsed["report_back_chars"],
        "inherit_context_chars": "unmeasured (not in log)",
        "per_agent": {
            aid: {"calls": len(a["calls"]), "coord": a["coord"], "work": a["work"]}
            for aid, a in agents.items()
        },
        "verdict": _verdict(len(children), total_coord, total_calls, child_work),
    }


#: Coordination share above which a child is not worth it at a 25-turn budget.
#: Chosen before looking at this batch's numbers; see docs/11 for the entry.
EXPENSIVE_SHARE = 0.15


def _verdict(children: int, coord: int, total: int, child_work: int) -> str:
    """One-line judgement, deliberately blunt.

    Args:
        children: Number of spawned children.
        coord: Coordination calls.
        total: Total calls in the run.
        child_work: Calls the children spent on the challenge.

    Returns:
        ``no_child`` / ``child_unproven`` / ``child_expensive`` / ``child_earned``.
    """
    if children == 0:
        return "no_child"
    if child_work == 0:
        return "child_unproven"
    if total and coord / total > EXPENSIVE_SHARE:
        return "child_expensive"
    return "child_earned"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Arguments; defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code: always 0 unless a path is unreadable.
    """
    ap = argparse.ArgumentParser(description="Measure child-agent coordination cost.")
    ap.add_argument("logs", nargs="+", help="run logs")
    ap.add_argument("--json", dest="json_out", help="write full results here")
    args = ap.parse_args(argv)

    results = []
    for name in args.logs:
        path = Path(name)
        if not path.is_file():
            print(f"[skip] {name}: not a file", file=sys.stderr)
            continue
        results.append(measure(path))

    for r in results:
        if not r.get("ok"):
            print(f"{r['log']}: {r.get('reason')}")
            continue
        print(
            f"{r['log']}: agents={r['agents']} children={r['children']} "
            f"calls={r['total_calls']} coord={r['coordination_calls']} "
            f"({r['coordination_share']:.1%}) child_work={r['child_work_calls']} "
            f"task_chars={r['spawn_task_chars']} -> {r['verdict']}"
        )

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
