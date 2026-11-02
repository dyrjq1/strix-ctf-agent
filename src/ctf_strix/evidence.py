"""Provenance gate for captured flags.

Two failure modes were observed on 2026-10-31:

* **CTFARENA-078, attempt 2** -- the model wrote a flag it never retrieved.
  ``FLAG{3f3f3f...}`` appeared in no tool output at all; the real answer was
  ``FLAG{0f0f0f...}``.  Nothing stopped it from being submitted if it had
  been phrased as a ``finish_scan`` argument.
* **CTFARENA-018, attempt 2** -- the model ``cat``-ed ``/tmp/flag.json``, left
  behind by an earlier run on the shared host, and submitted that.  The flag
  was real, just for a different challenge.

This module fixes the **first** one, because it is decidable from data the run
already has: a flag counts as *retrieved* only when the identical string
appeared in a tool output produced during this run.

It deliberately does **not** try to fix the second one.  Host ``/tmp`` is
shared between runs; telling a genuine solve apart from a stale local read
would need string heuristics, and those reject real solves that write a probe
script to ``/tmp`` and print the answer from it (CTFARENA-009 did exactly
that).  That has to be fixed by isolating the sandbox, not by guessing.

The ledger is orthogonal to :mod:`ctf_strix.flag_extract`:

* extraction answers "is this string a plausible answer *here*" (host
  proximity, recon leftovers, placeholders);
* the ledger answers "did this run actually see it".

Both gates must pass before a flag is submitted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctf_strix.flag_extract import FLAG_RE


@dataclass
class EvidenceLedger:
    """Flags actually observed in this run's tool output."""

    #: flag -> number of tool outputs that contained it
    observed: dict[str, int] = field(default_factory=dict)
    #: flags the model claimed but that never appeared in an output
    unsupported: list[str] = field(default_factory=list)

    def observe_output(self, text: str) -> list[str]:
        """Record every flag-shaped string present in one tool output.

        Args:
            text: Raw tool output.

        Returns:
            The flags found in this output (possibly empty).
        """
        found = FLAG_RE.findall(text or "")
        for flag in found:
            self.observed[flag] = self.observed.get(flag, 0) + 1
        return found

    def supports(self, flag: str | None) -> bool:
        """Whether ``flag`` was seen in at least one tool output."""
        if not flag:
            return False
        return self.observed.get(flag, 0) > 0

    def reject(self, flag: str | None) -> None:
        """Remember a claimed-but-unseen flag so it shows up in diagnostics."""
        if flag and flag not in self.unsupported:
            self.unsupported.append(flag)

    def summary(self) -> dict[str, object]:
        """Compact diagnostics for ``result.json`` / the run log."""
        return {
            "flags_observed": len(self.observed),
            "outputs_with_flag": sum(self.observed.values()),
            "unsupported_claims": list(self.unsupported),
        }
