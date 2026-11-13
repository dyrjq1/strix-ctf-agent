"""Target-absent fast fail: end the run when every path answers the same nothing.

## Why this exists

2026-11-06 platform run sent 95 ``exec_command`` curls at a host
that answered an identical Go-style ``404 page not found`` to every path.
``EnumerationGuard`` never fired: its counter is keyed per path *family*, and
every one of those paths was a different family, so every count stayed at 0.
The run burned the remaining wall clock instead of rotating to the next
challenge.  Two placeholder sample tasks (236-byte README,
no service behind the URL) left the agent guessing for 23 minutes.

Both failures share one path-independent signal: **the target is not there**.
It appears as many distinct paths answered by one identical, uninformative
body -- not as one family probed six times.  So this guard keys on the
response instead of on the request shape:

* the same body hash must be seen on ``TARGET_ABSENT_PATHS`` (6) *distinct*
  paths of the same origin;
* "uninformative" means any non-2xx/3xx answer whose body carries no
  application marker -- every such response counts, not only the
  404/410/502/503/504 "dead" set, which bypasses the marker check entirely;
* one 2xx/3xx, **an application-marker body**, or an **auth wall** (a 401/403
  answer, or an auth-shaped body when the tool hid the status line) from the
  host disarms the guard permanently -- a live target is never "absent"; the
  auth wall itself is ``journey_guard``'s business, not this guard's; and
* an answer already recorded also disarms it: the run has something to submit,
  so ending early would trade a score for wall clock.

## Hard stop, not a hint

The dead-host lesson (see :mod:`ctf_strix.enum_guard`) is that text
appended below the threshold changes nothing once the model has decided to
keep probing.  So the crossing call returns a short ``ERROR:`` line instead
of the tool output, and every later call to that origin is refused before the
underlying tool runs.  ``agent.py`` watches ``tripped`` and raises
:class:`TargetAbsent` from the event sink at the *next* round boundary, which
``main`` maps to ``stop_reason="target_absent"``.  Every output of the round
that tripped the guard has been consumed by then (the SDK queues events in
FIFO order, and a boundary event carries no item).  The hard stop costs one
extra generation: the next round's planned tool call is cancelled before it
runs.  If that generation breaches the output budget, ``stop_reason`` lands
on ``output_budget`` instead.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlsplit

from ctf_strix.nonweb import tcp_connect_state
from ctf_strix.probe_surface import NETWORK_TOOLS, is_probe_tool

if TYPE_CHECKING:
    from agents import FunctionTool


#: Marker this guard leaves on the tools it wrapped; ``guard_mount.verify_mount``
#: checks for it at run start so "wired but inert" is visible.
_MARK: Final = "_ctf_target_guarded"

#: How many distinct paths must repeat one identical uninformative body.
TARGET_ABSENT_PATHS: Final[int] = 6

#: How many failed *connections* to one ``host:port`` before ``tcp`` /
#: ``tcp_batch`` stop running for that origin.  A failed dial costs up to
#: 10s of wall clock (``nonweb.tcp`` caps it at ``min(10.0, window + 7.0)``),
#: so a black-holed service that is retried is the single most expensive way
#: to waste a run.  Three tries separates "wrong port / transient blip" from
#: "nothing is listening" without being trigger-happy.
#:
#: Cost model (updated for §4.144/§4.145, CROSS-CHECK 1): this counter sees
#: *dials* through the first-line classifier, and a dead try never reaches
#: the TLS probe -- the probe only runs after a plain round connected and
#: stayed silent, and a TLS-side failure still classifies as ``live``, so
#: the threshold cannot misfire on the extra connection.  What changed is
#: the run-level bill, not the per-try one: a silent-but-live target costs
#: the read window **plus** one 4s-capped auto-TLS probe connection that
#: this counter never sees.  "3 tries" still means 3 dials' worth of
#: dead budget; it no longer bounds the total tcp wall clock.
TCP_DEAD_CONNECTS: Final[int] = 3

#: How many DNS failures on one host before the whole run stops.  A name that
#: does not resolve is host-level: no port on it can answer, so this is the
#: only tcp outcome strong enough to end the round (see :meth:`stop_detail`).
TCP_DNS_STOPS: Final[int] = 3

#: Statuses that mean "this host does not serve this resource".  A 404 from
#: an application is still uninformative for *path discovery*, which is all
#: this guard is allowed to conclude.
_DEAD_STATUSES: Final[frozenset[int]] = frozenset({404, 410, 502, 503, 504})

#: Application markers.  Deliberately short and explicit: every entry is a
#: shape the repo already treats as "a real page answered".  A body carrying
#: one of these is not evidence that the target is absent.
_HTML_MARKERS: Final[tuple[str, ...]] = (
    "<!doctype",
    "<html",
    "<head",
    "<body",
    "<title",
    "<script",
)
_FRAMEWORK_MARKERS: Final[tuple[str, ...]] = (
    "__next_data__",
    "ng-version",
    "data-reactroot",
    "data-server-rendered",
    "data-v-",
    "<app-root",
    'id="root"',
)
#: Keys that make a JSON object an *error* object rather than application
#: data.  ``{"error": "not found"}`` is uninformative; ``{"users": []}`` is
#: an answer from a real service.
_ERROR_KEYS: Final[frozenset[str]] = frozenset(
    {"error", "errors", "detail", "message", "status", "statuscode", "code"}
)

#: Statuses that mean "the application is up and wants credentials".  A 401 or
#: 403 is an auth wall, not an absent host: the routing layer answered.  They
#: are deliberately *not* in ``_DEAD_STATUSES``, and before the auth branch
#: existed they fell through to the marker check -- where
#: ``{"error":"unauthorized"}``, a JSON object whose only key is in
#: ``_ERROR_KEYS``, has no marker and counted as "uninformative".  Six paths
#: behind one login wall were then enough to declare a live target absent and
#: refuse every later call to it (report WEB-3).
_AUTH_STATUSES: Final[frozenset[int]] = frozenset({401, 403})

#: The same signal when the tool hides the status line (plain ``curl -s``
#: prints only the body), so the body has to carry the verdict.  Kept narrow on
#: purpose: only phrases that say "authenticate first".  Generic failures
#: (``not found``, ``internal error``) must still count as uninformative.
_AUTH_BODY_RE: Final = re.compile(
    r"\b(?:unauthori[sz]ed|forbidden|not authenticated|authentication required"
    r"|login required|please (?:log|sign) ?in|access denied"
    r"|invalid credentials"
    r"|(?:invalid|missing|expired) (?:api[ _-]?)?(?:key|token|credentials)"
    r"|token (?:expired|required))\b",
    re.IGNORECASE,
)

#: Same URL shape the other guards use; stops at shell/JSON punctuation.
_URL_RE: Final = re.compile(r"https?://[^\s\"'<>|)}\]]+")

#: Status sources, in the order the tool surfaces print them: ``http_probe``
#: head, ``curl -i`` status line, ``curl -f`` failure text.
_STATUS_RES: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\[HTTP (\d{3})\]"),
    re.compile(r"\bHTTP/\d(?:\.\d)? (\d{3})\b"),
    re.compile(r"returned error: (\d{3})\b"),
)

#: Transport noise that changes on every call (see ``enum_guard``); hashing it
#: would make the same body look different every time.
_NOISE: Final[tuple[tuple[str, str], ...]] = (
    (r"Chunk ID: \S+", "Chunk ID: <id>"),
    (r"Wall time: [0-9.]+ ?(?:seconds|s)\b", "Wall time: <t>"),
    (r"/tmp/sandbox-\d+-\d+", "/tmp/sandbox"),
)

#: The first line of a tool result that is a *status head*, not body content.
_HEAD_RE: Final = re.compile(
    r"^(?:Chunk ID:|\[HTTP \d{3}\]|\[NO RESPONSE\]|HTTP/\d|Process exited)"
)


def _origin_and_path(args: str) -> tuple[str, str] | None:
    """Return ``(origin, path)`` for the first URL in the call arguments.

    The origin keeps the port: ``127.0.0.1:8080`` and ``127.0.0.1:9090`` are
    different targets and must never share a "this host is dead" verdict.
    The query is dropped on purpose -- ``/api?id=1`` .. ``/api?id=9`` is one
    path, and six ids on it are not the "six distinct paths" this guard needs.

    Args:
        args: the raw tool-argument blob.

    Returns:
        ``("https://host:port", "/path")``, or ``None`` when no URL is present.
    """
    match = _URL_RE.search(args or "")
    if match is None:
        return None
    url = match.group(0).rstrip(".,;:!?)]}'\"")
    try:
        parts = urlsplit(url)
    except ValueError:
        # Malformed URL (a truncated IPv6 literal is the common case): the
        # guard cannot reason about this path, so ignore it rather than crash.
        return None
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}".lower(), parts.path or "/"


#: Fallbacks for the tcp tools' arguments when the blob is not clean JSON.
#: Argument blobs are model-written, and a truncated blob is common enough
#: that a strict ``json.loads``-or-nothing would silently drop the guard.
_TCP_HOST_RE: Final = re.compile(r'"host"\s*:\s*"([^"]*)"')
_TCP_PORT_RE: Final = re.compile(r'"port"\s*:\s*(\d{1,5})')


def _tcp_origin(args: str) -> str | None:
    """Return ``host:port`` for a ``tcp`` / ``tcp_batch`` argument blob.

    Unlike an http URL, a raw socket target has no path and no scheme: the
    unit is exactly ``(host, port)``, and that pair is what the verdict is
    scoped to.  ``127.0.0.1:1337`` and ``127.0.0.1:1338`` are different
    targets, and one being closed says nothing about the other.

    Args:
        args: the raw tool-argument blob.

    Returns:
        A lowercase ``host:port`` key (IPv6 bracketed), or ``None`` when the
        blob does not name both a host and an in-range port.
    """
    if not args:
        return None
    host = ""
    port: int | None = None
    try:
        data = json.loads(args)
    except (TypeError, ValueError):
        data = None
    if isinstance(data, dict):
        raw_host = data.get("host")
        if isinstance(raw_host, str):
            host = raw_host.strip()
        raw_port = data.get("port")
        if isinstance(raw_port, int) and not isinstance(raw_port, bool):
            port = raw_port
        elif isinstance(raw_port, str) and raw_port.strip().isdigit():
            port = int(raw_port.strip())
    if not host:
        match = _TCP_HOST_RE.search(args)
        if match is not None:
            host = match.group(1).strip()
    if port is None:
        match = _TCP_PORT_RE.search(args)
        if match is not None:
            port = int(match.group(1))
    if not host or port is None or not 0 < port < 65536:
        return None
    key = host.lower()
    if ":" in key and not key.startswith("["):
        # Bare IPv6 literal: bracket it so ``host:port`` stays unambiguous.
        key = f"[{key}]"
    return f"{key}:{port}"


def _status_of(text: str) -> int | None:
    """Extract the HTTP status from a tool result, when the tool printed one.

    ``exec_command`` runs plain ``curl -s``, which prints only the body, so
    ``None`` is the normal answer there and the body/marker rule decides.

    Args:
        text: the tool result text.

    Returns:
        The status code, or ``None`` when no status line is present.
    """
    for pattern in _STATUS_RES:
        match = pattern.search(text)
        if match is not None:
            return int(match.group(1))
    return None


def _body_of(text: str) -> str:
    """Strip the transport head and hints, leaving what the server sent.

    Two shapes are handled: ``http_probe`` (``[HTTP 404] ...`` head, then
    ``hdr:`` / ``body:`` / ``next:`` lines) and ``exec_command`` (``Chunk ID``
    / ``Wall time`` / ``Process exited`` lines, then ``Output:`` and stdout).

    Args:
        text: the tool result text.

    Returns:
        The response body as printed, whitespace-trimmed.
    """
    for pattern, repl in _NOISE:
        text = re.sub(pattern, repl, text)
    first, sep, rest = text.partition("\n")
    if sep and _HEAD_RE.match(first):
        text = rest
    kept = [
        line
        for line in text.splitlines()
        if not line.startswith(("hdr: ", "next: "))
    ]
    body = "\n".join(kept)
    marker = re.search(r"^Output:\s*$", body, re.M)
    if marker is not None:
        body = body[marker.end() :]
    body = body.strip()
    if re.match(r"HTTP/\d(?:\.\d)? \d{3}", body):
        # ``curl -i`` keeps the status line and the whole header block.  The
        # headers carry per-request noise (``Date``, ``Set-Cookie``) that would
        # make one fixed body hash differently every time, so drop everything
        # through the first blank line (the end of the header block).
        blank = re.search(r"\r?\n\r?\n", body)
        if blank is not None:
            body = body[blank.end() :]
        else:
            # No blank line after the status line, so everything that is left
            # is header.  Upstream joins ``splitlines()`` with ``\n`` and the
            # ``strip()`` above already ate the trailing blank line, which
            # gives three shapes the same look: a body-less response
            # (``Content-Length: 0`` 404s are common), ``curl -I`` / HEAD
            # (headers only, always) and truncated output.  Keeping the
            # headers would hash per-request noise (``Date``, ``Set-Cookie``)
            # and the same dead endpoint would never hash the same twice.
            body = ""
    body = re.sub(r"^\s*body:\s*", "", body.strip())
    return body.strip()


def _has_app_marker(body: str) -> bool:
    """True when ``body`` looks like a real application answered.

    Args:
        body: the response body.

    Returns:
        True for an HTML document, a known framework marker, or JSON that is
        not an error object.
    """
    low = body.lower()
    if any(marker in low for marker in _HTML_MARKERS):
        return True
    if any(marker in low for marker in _FRAMEWORK_MARKERS):
        return True
    stripped = body.strip()
    if stripped.startswith(("{", "[")):
        try:
            data = json.loads(stripped)
        except ValueError:
            return False
        if isinstance(data, list):
            return True
        if isinstance(data, dict):
            return any(str(key).lower() not in _ERROR_KEYS for key in data)
    return False


def _is_auth_wall(status: int | None, body: str) -> bool:
    """True when the answer says "authenticate first", not "nothing here".

    An auth wall is a *live* application: the routing layer answered and asked
    for credentials.  Counting it as an uninformative response lets six paths
    behind one login wall declare a working target absent (report WEB-3).

    Args:
        status: the HTTP status when the tool printed one, else ``None``.
        body: the response body as printed.

    Returns:
        True for a 401/403, or for an auth-shaped body when the status line is
        hidden (plain ``curl -s``).  A status that is present but is not an
        auth status decides on its own -- the body is not consulted.
    """
    if status in _AUTH_STATUSES:
        return True
    if status is not None:
        return False
    return _AUTH_BODY_RE.search(body) is not None


def _body_hash(body: str) -> str:
    """Hash the body exactly; identical bodies are the whole point."""
    return hashlib.sha1(body.encode("utf-8", "replace")).hexdigest()


class TargetAbsent(BaseException):
    """Every path of the target answered with the same non-answer.

    ``BaseException`` for the same reason as :class:`agent.IdleTimeout`: the
    runner and the tool wrappers are full of ``except Exception``, and a
    swallowed stop would hand control back to the probing loop.

    Evidence: one dead-host run (95 identical 404s, 2026-11-06) and the
    placeholder samples above (23 minutes of guessing).
    """

    def __init__(self, message: str, *, origin: str = "", paths: int = 0) -> None:
        super().__init__(message)
        self.origin = origin
        self.paths = paths


class TargetAbsentGuard:
    """Count distinct paths that got one identical uninformative response.

    Attributes:
        tripped_origin: the origin declared absent, or ``None``.
        observations: classified probe results seen (diagnostics).
        blocked_calls: later calls refused without running the tool.
    """

    def __init__(self, threshold: int = TARGET_ABSENT_PATHS) -> None:
        self.threshold = max(int(threshold), 2)
        #: origin -> body hash -> distinct paths that produced it.
        self._paths: dict[str, dict[str, set[str]]] = {}
        #: Origins that answered 2xx/3xx at least once.  Never fire there.
        self._alive: set[str] = set()
        #: ``host:port`` -> failure kind -> count (see ``nonweb.tcp_connect_state``).
        self._tcp_fail: dict[str, dict[str, int]] = {}
        #: Origins whose tcp tools are now refused outright.
        self._tcp_dead: set[str] = set()
        #: Subset of ``_tcp_dead`` whose verdict is host-level (DNS), so its
        #: message may say "report as absent" rather than "try another port".
        self._tcp_final: set[str] = set()
        #: The ``TargetAbsent`` reason when the trip came from tcp, else "".
        self._tcp_stop_note: str = ""
        self._answer_recorded: bool = False
        self.tripped_origin: str | None = None
        self.observations: int = 0
        self.blocked_calls: int = 0

    @property
    def tripped(self) -> bool:
        """True once the target has been declared absent."""
        return self.tripped_origin is not None

    def note_answer(self) -> None:
        """Latch "an answer is already recorded"; the guard must never fire."""
        self._answer_recorded = True

    def refusal(self, args: str) -> str | None:
        """Return the hard error when this call targets a tripped origin.

        Scoped by origin on purpose: a process that runs several challenges in
        a row must not let challenge A's verdict block challenge B's host.

        Args:
            args: the raw tool-argument blob.

        Returns:
            The short error text, or ``None`` when the call may run.
        """
        if self.tripped_origin is None:
            return None
        where = _origin_and_path(args)
        if where is None or where[0] != self.tripped_origin:
            return None
        self.blocked_calls += 1
        return self._blocked_error()

    def tcp_refusal(self, tool_name: str, args: str) -> str | None:
        """Return the hard error when this tcp call targets a dead ``host:port``.

        Separate from :meth:`refusal` because the key is ``host:port`` parsed
        out of tool arguments, not a URL scraped from a probe payload -- the
        two share no code path, and folding them together is how the http
        rule "six paths, one body" would end up applied to sockets.

        Args:
            tool_name: registered tool name.
            args: the raw tool-argument blob.

        Returns:
            The short error text, or ``None`` when the call may run.
        """
        if tool_name not in NETWORK_TOOLS:
            return None
        origin = _tcp_origin(args)
        if origin is None or origin not in self._tcp_dead:
            return None
        self.blocked_calls += 1
        return self._tcp_blocked_error(origin)

    def finish(self, tool_name: str, args: str, result: Any) -> str | None:
        """Classify one probe result.

        Args:
            tool_name: registered tool name.
            args: the raw tool-argument blob.
            result: whatever the tool returned.

        Returns:
            The hard error on the call that crosses the threshold, else
            ``None``.
        """
        if tool_name in NETWORK_TOOLS:
            return self._tcp_finish(tool_name, args, result)
        if self.tripped or self._answer_recorded or not is_probe_tool(tool_name):
            return None
        where = _origin_and_path(args)
        if where is None:
            return None
        origin, path = where
        text = result if isinstance(result, str) else str(result)
        if text.startswith("ERROR: ["):
            # A guard's own hard refusal is not an answer from the target.
            # Both shapes start with this prefix: enum_guard's hard block
            # ("ERROR: [ENUMERATION GUARD] ...", returned *instead of* the
            # tool output) and this guard's own later refusals
            # ("ERROR: [TARGET ABSENT] ...", unreachable here because a
            # tripped guard returns at the top).  Counting it would let six
            # different paths blocked by the enumeration guard look like six
            # distinct paths answered by one dead target -- a live target
            # killed by its own guard, and the answer never submitted.
            # journey_guard / sweep_guard only *append* their hint after the
            # real result ("{result}{hint}"), so they never reach this gate.
            return None

        status = _status_of(text)
        if status is not None and 200 <= status < 400:
            # A live target is never "absent".  Drop what we counted so far:
            # those paths may simply have been the wrong ones.
            self._alive.add(origin)
            self._paths.pop(origin, None)
            return None
        if origin in self._alive:
            return None

        body = _body_of(text)
        if status is None and not body:
            return None
        if _is_auth_wall(status, body):
            # An auth wall is a live application.  Latch it like a 2xx: an
            # application asking for credentials is never "absent", and a
            # later run of identical 404s from the same host must not
            # resurrect the verdict.  Stopping the *probing* behind that wall
            # is journey_guard's job (`_WARN_AFTER` / `_HARD_AFTER` payloads),
            # not this guard's -- the two signals were being conflated.
            self._alive.add(origin)
            self._paths.pop(origin, None)
            return None
        if status not in _DEAD_STATUSES and _has_app_marker(body):
            # A marker body means a real application answered.  When the tool
            # hides the status line (plain ``curl -s`` -- the ``exec_command``
            # shape), this is the only liveness signal: latch it so later
            # identical 404s cannot declare a live target absent.
            self._alive.add(origin)
            self._paths.pop(origin, None)
            return None

        self.observations += 1
        paths = self._paths.setdefault(origin, {}).setdefault(_body_hash(body), set())
        paths.add(path)
        if len(paths) >= self.threshold:
            self.tripped_origin = origin
            return self._blocked_error()
        return None

    def _tcp_finish(self, tool_name: str, args: str, result: Any) -> str | None:
        """Classify one ``tcp`` / ``tcp_batch`` result.

        The http rule in :meth:`finish` needs six distinct *paths*.  Sockets
        have no paths, so the repeatable unit is the connection attempt itself:
        the counter lives on ``host:port`` and is keyed by what the attempt did
        (``nonweb.tcp_connect_state``), because a timeout and a refused port are
        different evidence even though both mean "no service there right now".

        Two outcomes carry different weight and get different verdicts:

        - **DNS failure** is host-level.  Nothing on that name can answer, so
          three of them end the round via ``tripped_origin`` -- the same hook
          ``agent.py`` already watches for the http verdict.
        - **Refused / timed out / unreachable** is port-level.  The box may be
          up with the real service on another port, so the origin is refused
          and the round keeps running.  Calling that "target absent" would be
          the same kind of lie this guard exists to remove.

        Args:
            tool_name: registered tool name (already known to be a network tool).
            args: the raw tool-argument blob.
            result: whatever the tool returned.

        Returns:
            The hard error on the call that crosses a threshold, else ``None``.
        """
        if self.tripped or self._answer_recorded:
            return None
        text = result if isinstance(result, str) else str(result)
        origin = _tcp_origin(args)
        if origin is None:
            return None
        state = tcp_connect_state(text)
        if state is None:
            # Argument errors ("host is empty", "invalid port", "payloads is
            # empty") never reached the network.  Counting them would let a
            # malformed call kill a host that was never dialled.
            return None
        self.observations += 1
        if state == "live":
            # A completed handshake clears the origin outright -- including the
            # TLS/send failures the classifier calls live, since those only
            # happen on a socket that did connect.
            self._tcp_fail.pop(origin, None)
            self._tcp_dead.discard(origin)
            self._tcp_final.discard(origin)
            return None

        counts = self._tcp_fail.setdefault(origin, {})
        counts[state] = counts.get(state, 0) + 1
        attempts = sum(counts.values())
        if state == "dns" and counts["dns"] >= TCP_DNS_STOPS:
            self._tcp_dead.add(origin)
            self._tcp_final.add(origin)
            self.tripped_origin = origin
            self._tcp_stop_note = (
                f"target absent: {origin[:60]} did not resolve as a hostname on "
                f"{counts['dns']} tcp attempts -- a DNS failure is host-level, "
                "so no port on it can answer"
            )
            return self._tcp_blocked_error(origin)
        if attempts >= TCP_DEAD_CONNECTS:
            self._tcp_dead.add(origin)
            return self._tcp_blocked_error(origin)
        return None

    def stop_detail(self) -> str:
        """One-line reason for the ``TargetAbsent`` exception."""
        if self._tcp_stop_note:
            # The http wording below -- "the same uninformative response on N
            # distinct paths" -- is false for a socket: there were no paths and
            # no response.  A stop reason that misdescribes its own evidence is
            # what this guard is supposed to prevent, not produce.
            return self._tcp_stop_note
        origin = self.tripped_origin or "target"
        return (
            f"target absent: {origin} answered the same uninformative response "
            f"on {self.threshold}+ distinct paths with no 2xx/3xx"
        )

    def _tcp_blocked_error(self, origin: str) -> str:
        """Build the short hard-reject message for a dead ``host:port``."""
        short = origin[:60]
        if origin in self._tcp_final:
            return (
                f"ERROR: [TCP UNREACHABLE] {short} did not resolve as a hostname "
                f"on {TCP_DNS_STOPS} attempts. DNS is host-level: no port on this "
                "host can answer. Stop probing it and report the target as absent."
            )
        return (
            f"ERROR: [TCP UNREACHABLE] {short} never accepted a connection on "
            f"{TCP_DEAD_CONNECTS} attempts. Stop probing this host:port. If the "
            "task names a different port, use that one; otherwise report this "
            "service as down."
        )

    def _blocked_error(self) -> str:
        """Build the short hard-reject message (well under 400 characters)."""
        origin = (self.tripped_origin or "target")[:60]
        return (
            f"ERROR: [TARGET ABSENT] {origin} gave the same uninformative "
            f"response on {self.threshold} distinct paths and never returned "
            "2xx/3xx. Stop probing this target: report it as absent instead "
            "of enumerating more paths."
        )


def install() -> TargetAbsentGuard:
    """Wrap every tool entry point with the target-absent guard.

    Must run after ``guard_mount.install_mount_hook()`` for the same reason as
    ``enum_guard.install``: ``exec_command`` goes through the Shell capability
    and bypasses ``factory._with_bounded_result`` unless the mount hook has
    been installed first.

    Returns:
        The installed guard, for diagnostics and tests.
    """
    from strix.agents import factory

    guard = TargetAbsentGuard()
    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if getattr(tool, _MARK, False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            refusal = guard.refusal(raw_input)
            if refusal is None:
                refusal = guard.tcp_refusal(tool.name, raw_input)
            if refusal is not None:
                # Hard block: the tool never runs again for this origin.
                return refusal
            result = await inner(ctx, raw_input)
            blocked = guard.finish(tool.name, raw_input, result)
            if blocked is not None:
                # Replace the output: this is the signal, not a hint.
                return blocked
            return result

        tool.on_invoke_tool = invoke
        setattr(tool, _MARK, True)
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard

