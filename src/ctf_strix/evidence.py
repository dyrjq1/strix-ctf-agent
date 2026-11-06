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

One more failure mode does not need heuristics: **self-echo**.  A model can
write its own guess into a command, a script argument, or a submission
payload; the tool then prints it back, and the old ledger counted that as a
retrieval.  This is decidable from data the run already has -- the call's own
arguments -- so an observation is marked *echoed* when the same literal was
already in that invocation's arguments.  Echoed observations never increment
the support count; a later output whose arguments did **not** contain the
literal restores it normally (CTFARENA-009's ``/tmp`` probe still counts).

The ledger is orthogonal to :mod:`ctf_strix.flag_extract`:

* extraction answers "is this string a plausible answer *here*" (host
  proximity, recon leftovers, placeholders);
* the ledger answers "did this run actually see it".

Both gates must pass before a flag is submitted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctf_strix.flag_extract import FLAG_RE, is_placeholder


@dataclass
class EvidenceLedger:
    """Flags actually observed in this run's tool output."""

    #: flag -> number of tool outputs that contained it without echoing it
    #: back from the call's own arguments
    observed: dict[str, int] = field(default_factory=dict)
    #: flag -> number of outputs that only replayed a literal which was
    #: already present in that call's arguments
    echoed: dict[str, int] = field(default_factory=dict)
    #: flags the model claimed but that never appeared in an output
    unsupported: list[str] = field(default_factory=list)

    def observe_output(self, text: str, arguments: str | None = None) -> list[str]:
        """Record every *real* flag-shaped string present in one tool output.

        Args:
            text: Raw tool output.
            arguments: Raw arguments of the tool call that produced ``text``,
                when known.  A flag found in both is a self-echo: the output
                merely repeated what the model already wrote, so it does not
                count as retrieved evidence for this observation.  Passing
                ``None`` keeps the legacy behaviour (count everything) for
                callers that cannot pair an output with its call.

        Returns:
            The flags found in this output (possibly empty).
        """
        # Template placeholders (``FLAG{…}``, all-x bodies) never count as
        # evidence.  Without this, an agent that greps its own source reads the
        # example in a docstring and the ledger "supports" it — which is exactly
        # how an impossible challenge was reported as solved on 2026-11-06.
        found = [flag for flag in FLAG_RE.findall(text or "") if not is_placeholder(flag)]
        from_args = set(FLAG_RE.findall(arguments or ""))
        # One output is one observation: a flag printed twice by the same call
        # must not inflate the diagnostic counters.
        for flag in dict.fromkeys(found):
            if flag in from_args:
                self.echoed[flag] = self.echoed.get(flag, 0) + 1
            else:
                self.observed[flag] = self.observed.get(flag, 0) + 1
        return found

    def supports(self, flag: str | None) -> bool:
        """Whether ``flag`` was seen in at least one non-echoed tool output.

        Echo bookkeeping is deliberately not permanent: an earlier echoed
        observation does not block a later output where the call's arguments
        did not contain the literal, which is what a genuine retrieval looks
        like.
        """
        if not flag:
            return False
        return self.observed.get(flag, 0) > 0

    def echoed_only(self, flag: str | None) -> bool:
        """Whether ``flag`` was only ever replayed from a call's arguments."""
        if not flag:
            return False
        return flag in self.echoed and self.observed.get(flag, 0) == 0

    def reject(self, flag: str | None) -> None:
        """Remember a claimed-but-unseen flag so it shows up in diagnostics."""
        if flag and flag not in self.unsupported:
            self.unsupported.append(flag)

    def summary(self) -> dict[str, object]:
        """Compact diagnostics for ``result.json`` / the run log."""
        return {
            "flags_observed": len(self.observed),
            "outputs_with_flag": sum(self.observed.values()),
            "flags_echoed": len(self.echoed),
            "echoed_observations": sum(self.echoed.values()),
            "retrieved_flags": sorted(self.observed),
            "echoed_only_flags": sorted(
                flag for flag in self.echoed if self.observed.get(flag, 0) == 0
            ),
            "unsupported_claims": list(self.unsupported),
        }
