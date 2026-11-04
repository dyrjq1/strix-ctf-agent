"""Platform attachment channels: REST challenge/instance and MCP.

The player REST API is the first choice, but the token a run receives is not
guaranteed to be accepted at every endpoint: the challenge-level listing can
answer ``403`` while the same user can read it interactively.  The platform
still ships an MCP client configuration (``mcp.json``) exposing the very same
files, and instance-scoped REST routes exist for per-team artifacts.  This
module keeps those three small channels together so the caller can degrade
per file instead of giving up on the whole challenge.

Design rules:

* Every function returns the same :class:`ChannelResult`; nothing here writes
  to disk.  The caller owns the destination directory and reuses its atomic
  writer, so one bad channel cannot leave half a file behind.
* Failures are data, not exceptions.  The caller decides whether another
  channel is worth trying.
* A token never appears in a log line.  Error strings only carry HTTP status,
  exception type and short server text; :func:`redact` is applied by callers
  that may know more secrets.
* Base64 is decoded only when the *structure* says so (``resource.blob`` or an
  explicit ``encoding`` field), never because a string looks like base64.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

#: One attachment may not exceed this.  The response cap is larger because a
#: base64 body is ~4/3 of the decoded size.  Both are deliberately finite: a
#: hostile or broken platform must not turn the fetch into an OOM.
MAX_ATTACHMENT_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 24 * 1024 * 1024

_USER_AGENT = "ctfy-agent"
_HTTP_TIMEOUT_FLOOR = 0.1
_EXPAND = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_MCP_INIT_HINTS = (400, 406, 415, 428)
_MCP_AUTH_STATUS = (401, 403, 429)
_STREAMABLE_TYPES = {"", "http", "streamable-http", "streamablehttp", "streamable_http"}
_INITIALIZED_NOTIFICATION = {"jsonrpc": "2.0", "method": "notifications/initialized"}


@dataclass
class FileSpec:
    """One entry from a listing: a bare name plus the size it claims."""

    name: str
    size: int | None = None
    per_team: bool = False


@dataclass
class ChannelResult:
    """What one channel managed to list and download."""

    channel: str
    listed: bool = False
    files: list[FileSpec] = field(default_factory=list)
    blobs: dict[str, bytes] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    fatal: bool = False

    def status(self) -> str:
        """One short line for the run log; never includes a secret."""
        listed = "listed" if self.listed else "unlisted"
        return (
            f"channel={self.channel} {listed} files={len(self.files)} "
            f"fetched={len(self.blobs)} fatal={self.fatal}"
        )


@dataclass
class McpConfig:
    """The platform-supplied MCP endpoint and headers (already expanded)."""

    url: str
    headers: dict[str, str]
    secrets: tuple[str, ...] = ()


def redact(text: object, secrets: Iterable[str] = ()) -> str:
    """Replace every known secret in ``text``; also flatten newlines."""
    out = str(text or "").replace("\r", " ").replace("\n", " ")
    for secret in secrets:
        if secret:
            out = out.replace(secret, "***")
    return out


def safe_attachment_name(raw: object) -> str | None:
    """Return a bare file name, or ``None`` when the wire supplied a path.

    A name is a path component, not a path: ``../``, absolute paths, drive
    letters, separators and control characters are all refused.  This runs on
    list results *and* on the name echoed by a download response, so neither
    side can steer the writer outside ``work/attachments``.
    """
    name = str(raw or "").strip()
    if not name or name in {".", ".."}:
        return None
    if "/" in name or "\\" in name or ":" in name:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        return None
    if Path(name).name != name:
        return None
    return name


def _coerce_size(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _clip(text: object, limit: int = 200) -> str:
    return str(text or "").replace("\r", " ").replace("\n", " ")[:limit]


def _timeout(deadline: float) -> float:
    return max(deadline - time.monotonic(), _HTTP_TIMEOUT_FLOOR)


def _budget_spent(deadline: float) -> bool:
    return time.monotonic() >= deadline


def _read_limited(response: Any, limit: int) -> bytes:
    """Read at most ``limit`` bytes; raise when the peer sends more."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(65536, limit - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ValueError(f"response larger than {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _http(
    url: str,
    headers: Mapping[str, str],
    *,
    timeout: float,
    limit: int = MAX_RESPONSE_BYTES,
    method: str = "GET",
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Perform one request and always close the response, including errors."""
    request = urllib.request.Request(
        url, data=body, headers=dict(headers), method=method
    )
    response = None
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
        status = getattr(response, "status", 200)
        response_headers = {
            str(key).lower(): value for key, value in (response.headers or {}).items()
        }
        payload = _read_limited(response, limit)
        return status, response_headers, payload
    except urllib.error.HTTPError as exc:
        try:
            response_headers = {
                str(key).lower(): value
                for key, value in (exc.headers or {}).items()
            }
            payload = _read_limited(exc, min(limit, 8192))
            return exc.code, response_headers, payload
        finally:
            exc.close()
    finally:
        if response is not None:
            response.close()


def _json_object(body: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


def _parse_listing(body: bytes) -> list[FileSpec] | None:
    """Parse the shared ``{"files": [...]}`` listing shape."""
    payload = _json_object(body)
    if payload is None:
        return None
    files = payload.get("files")
    if not isinstance(files, list):
        return None
    return _specs_from_rows(files)


def _specs_from_rows(files: list[Any]) -> list[FileSpec]:
    out: list[FileSpec] = []
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("filename") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(
            FileSpec(
                name=name,
                size=_coerce_size(item.get("size")),
                per_team=bool(item.get("per_team", False)),
            )
        )
    return out


def _rest_headers(token: str, *, accept: str = "application/json") -> dict[str, str]:
    headers = {"Accept": accept, "User-Agent": _USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _download_rest(
    base: str,
    specs: Mapping[str, FileSpec],
    *,
    should_skip: Callable[[str], bool] | None,
    deadline: float,
    token: str,
    result: ChannelResult,
) -> None:
    headers = _rest_headers(token, accept="application/octet-stream")
    for raw_name, spec in specs.items():
        if _budget_spent(deadline):
            result.errors.append("budget spent before every file was fetched")
            break
        name = safe_attachment_name(raw_name)
        if name is None:
            result.errors.append(f"unsafe attachment name refused: {raw_name!r}")
            continue
        if should_skip is not None and should_skip(name):
            continue
        url = f"{base}/{urllib.parse.quote(name, safe='')}"
        try:
            status, _headers, blob = _http(
                url, headers, timeout=_timeout(deadline), limit=MAX_ATTACHMENT_BYTES
            )
        except Exception as exc:  # noqa: BLE001 - one file must not stop the rest
            result.errors.append(f"{name}: {type(exc).__name__}: {_clip(exc)}")
            continue
        if status != 200:
            result.errors.append(f"{name}: HTTP {status}")
            continue
        if not blob:
            result.errors.append(f"{name}: empty body")
            continue
        declared = spec.size
        if declared is not None and len(blob) != declared:
            result.errors.append(
                f"{name}: size mismatch (listed {declared}, got {len(blob)})"
            )
            continue
        result.blobs[name] = blob


def _fetch_rest(
    label: str,
    base: str,
    token: str,
    *,
    names: list[str] | None,
    should_skip: Callable[[str], bool] | None,
    deadline: float,
) -> ChannelResult:
    result = ChannelResult(channel=label)
    if names is None:
        if _budget_spent(deadline):
            result.errors.append("budget spent before listing")
            return result
        try:
            status, _headers, body = _http(
                base, _rest_headers(token), timeout=_timeout(deadline)
            )
        except Exception as exc:  # noqa: BLE001 - caller keeps the old path
            result.errors.append(f"list {type(exc).__name__}: {_clip(exc)}")
            return result
        if status != 200:
            result.errors.append(f"list HTTP {status}")
            result.fatal = True
            return result
        listing = _parse_listing(body)
        if listing is None:
            result.errors.append("list returned malformed JSON")
            result.fatal = True
            return result
        result.listed = True
        result.files = listing
        names = [spec.name for spec in listing]

    specs: dict[str, FileSpec] = {}
    for name in names:
        specs.setdefault(name, FileSpec(name=name))
    if not result.listed:
        # Names came from task.json or from a previous channel; keep them so
        # the caller can see what it asked for even when nothing downloaded.
        result.files = list(specs.values())
    _download_rest(
        base,
        specs,
        should_skip=should_skip,
        deadline=deadline,
        token=token,
        result=result,
    )
    return result


def fetch_rest_challenge(
    platform: str,
    challenge_id: str,
    token: str,
    *,
    names: list[str] | None = None,
    should_skip: Callable[[str], bool] | None = None,
    deadline: float,
) -> ChannelResult:
    """List/download ``/api/v1/challenges/{id}/attachments``."""
    base = (
        f"{platform}/api/v1/challenges/"
        f"{urllib.parse.quote(challenge_id, safe='')}/attachments"
    )
    return _fetch_rest(
        "rest-challenge",
        base,
        token,
        names=names,
        should_skip=should_skip,
        deadline=deadline,
    )


def fetch_rest_instance(
    platform: str,
    instance_id: str,
    token: str,
    *,
    names: list[str] | None = None,
    should_skip: Callable[[str], bool] | None = None,
    deadline: float,
) -> ChannelResult:
    """List/download ``/api/v1/instances/{id}/attachments`` (per-team files)."""
    base = (
        f"{platform}/api/v1/instances/"
        f"{urllib.parse.quote(instance_id, safe='')}/attachments"
    )
    return _fetch_rest(
        "rest-instance",
        base,
        token,
        names=names,
        should_skip=should_skip,
        deadline=deadline,
    )


def load_mcp_config(
    work: Path, environ: Mapping[str, str] | None = None
) -> tuple[McpConfig | None, str]:
    """Read ``work/mcp.json`` and expand ``${VAR}`` in the URL and headers.

    The platform writes this file; it is the authority on both the endpoint
    and the auth header.  Encoding a different endpoint here would silently
    bypass whatever the platform intends, so a missing/broken file simply
    disables the MCP channel.
    """
    env = os.environ if environ is None else environ
    path = work / "mcp.json"
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, "mcp.json missing"
    except OSError as exc:
        return None, f"mcp.json unreadable: {type(exc).__name__}"
    try:
        data = json.loads(raw)
    except ValueError:
        return None, "mcp.json is not valid JSON"
    if not isinstance(data, dict):
        return None, "mcp.json is not an object"
    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        return None, "mcp.json has no mcpServers"
    server: dict[str, Any] | None = None
    candidate = servers.get("ctfy")
    if isinstance(candidate, dict):
        server = candidate
    else:
        for value in servers.values():
            if isinstance(value, dict):
                server = value
                break
    if server is None:
        return None, "mcp.json has no usable server entry"
    kind = str(server.get("type") or "").strip().lower()
    if kind not in _STREAMABLE_TYPES:
        return None, f"mcp server type {kind!r} is not streamable HTTP"
    raw_url = str(server.get("url") or "").strip()
    if not raw_url:
        return None, "mcp server has no url"

    missing: list[str] = []

    def expand(value: str) -> str:
        def repl(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in env or env[key] == "":
                missing.append(key)
                return match.group(0)
            return env[key]

        return _EXPAND.sub(repl, value)

    url = expand(raw_url)
    raw_headers = server.get("headers")
    headers: dict[str, str] = {}
    if isinstance(raw_headers, dict):
        for key, value in raw_headers.items():
            if isinstance(key, str) and isinstance(value, (str, int, float)):
                headers[key] = expand(str(value))
    if missing:
        return None, "unexpanded env var(s): " + ", ".join(sorted(set(missing)))
    if "${" in url or any("${" in value for value in headers.values()):
        return None, "unexpanded template in mcp.json"
    if not url.lower().startswith(("http://", "https://")):
        return None, "mcp url is not absolute HTTP(S)"
    if not any(key.lower() == "authorization" for key in headers):
        return None, "mcp server has no Authorization header"
    secrets: list[str] = []
    for key, value in headers.items():
        if key.lower() == "authorization":
            secrets.append(value)
            parts = value.split(" ", 1)
            if len(parts) == 2 and parts[1]:
                secrets.append(parts[1])
    return McpConfig(url=url, headers=headers, secrets=tuple(dict.fromkeys(secrets))), ""


class _McpError(Exception):
    pass


class _McpHttpError(_McpError):
    def __init__(self, status: int, body: bytes) -> None:
        super().__init__(f"HTTP {status}: {_clip(body.decode('utf-8', 'replace'))}")
        self.status = status


class _McpRpcError(_McpError):
    def __init__(self, code: object, message: object) -> None:
        super().__init__(f"JSON-RPC error {code}: {_clip(message)}")
        self.code = code
        self.message = str(message or "")

    def looks_like_session(self) -> bool:
        text = self.message.lower()
        return any(word in text for word in ("initializ", "session", "protocol"))


class _McpToolError(_McpError):
    pass


class _McpProtocolError(_McpError):
    pass


def _sse_events(body: bytes) -> list[Any]:
    """Split a Streamable-HTTP SSE body into JSON values.

    A ``data:`` field may span several lines; the event ends at a blank line.
    Joining line by line instead would fail on exactly the responses that
    carry a pretty-printed JSON document.
    """
    text = body.decode("utf-8", "replace")
    events: list[Any] = []
    data: list[str] = []
    for line in text.splitlines():
        if line == "":
            if data:
                events.append(_decode_sse_data(data))
                data = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
    if data:
        events.append(_decode_sse_data(data))
    return events


def _decode_sse_data(lines: list[str]) -> Any:
    block = "\n".join(lines).strip()
    if not block:
        return None
    try:
        return json.loads(block)
    except ValueError:
        return None


def _decode_rpc_body(body: bytes, content_type: str, want_id: int) -> dict[str, Any]:
    raw = body.lstrip()
    use_sse = "text/event-stream" in content_type or raw.startswith(
        (b"event:", b"data:", b":")
    )
    if use_sse:
        events = _sse_events(body)
        if not events:
            raise _McpProtocolError("SSE body contained no data event")
        for event in events:
            if isinstance(event, dict) and event.get("id") == want_id:
                return event
        raise _McpProtocolError("SSE response id mismatch")
    try:
        message = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeError):
        raise _McpProtocolError(
            f"response is not JSON (Content-Type={content_type or 'none'})"
        ) from None
    if not isinstance(message, dict):
        raise _McpProtocolError("response is not a JSON object")
    if message.get("id") != want_id:
        raise _McpProtocolError("response id mismatch")
    return message


class _McpSession:
    """A single Streamable-HTTP JSON-RPC exchange, no framework."""

    def __init__(self, config: McpConfig, deadline: float) -> None:
        self.config = config
        self.deadline = deadline
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self._next_id = 0
        self._initialized = False

    def _headers(self) -> dict[str, str]:
        headers = dict(self.config.headers)
        headers.setdefault("Content-Type", "application/json")
        headers.setdefault("Accept", "application/json, text/event-stream")
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        return headers

    def _post(
        self, payload: dict[str, Any], *, expect_response: bool = True
    ) -> tuple[dict[str, str], bytes]:
        if _budget_spent(self.deadline):
            raise _McpProtocolError("budget spent before request")
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        status, headers, response = _http(
            self.config.url,
            self._headers(),
            timeout=_timeout(self.deadline),
            method="POST",
            body=body,
        )
        session = headers.get("mcp-session-id")
        if session:
            self.session_id = session
        if expect_response:
            if status != 200:
                raise _McpHttpError(status, response)
        elif status not in {200, 202, 204}:
            raise _McpHttpError(status, response)
        return headers, response

    def _rpc(self, method: str, params: dict[str, Any] | None) -> Any:
        self._next_id += 1
        request_id = self._next_id
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        headers, body = self._post(payload)
        message = _decode_rpc_body(body, headers.get("content-type", ""), request_id)
        if "error" in message:
            error = message.get("error") or {}
            raise _McpRpcError(error.get("code"), error.get("message"))
        return message.get("result")

    def initialize(self) -> None:
        result = self._rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": _USER_AGENT, "version": "1.0"},
            },
        )
        if isinstance(result, dict):
            version = result.get("protocolVersion")
            if isinstance(version, str) and version:
                self.protocol_version = version
        self._initialized = True
        try:
            self._post(_INITIALIZED_NOTIFICATION, expect_response=False)
        except _McpError:
            pass

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        params = {"name": name, "arguments": arguments}
        try:
            return self._rpc("tools/call", params)
        except _McpHttpError as exc:
            if exc.status not in _MCP_INIT_HINTS or self._initialized:
                raise
        except _McpRpcError as exc:
            if not exc.looks_like_session() or self._initialized:
                raise
        self.initialize()
        return self._rpc("tools/call", params)


def _text_of(result: Mapping[str, Any]) -> str:
    pieces: list[str] = []
    for block in result.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text":
            pieces.append(str(block.get("text") or ""))
    return " ".join(pieces)


def _result_payload(result: Mapping[str, Any]) -> dict[str, Any] | None:
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured
    for block in result.get("content") or []:
        if not isinstance(block, dict) or block.get("type") != "text":
            continue
        text = str(block.get("text") or "").strip()
        if not text or text[0] not in "{[":
            continue
        try:
            value = json.loads(text)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _parse_mcp_listing(result: Mapping[str, Any]) -> list[FileSpec] | None:
    payload = _result_payload(result)
    if payload is None:
        return None
    files = payload.get("files")
    if not isinstance(files, list):
        return None
    return _specs_from_rows(files)


def _decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise _McpToolError("content is not valid base64") from None


def _decode_payload(payload: Mapping[str, Any]) -> tuple[bytes, int | None]:
    content = payload.get("content")
    if not isinstance(content, str):
        raise _McpToolError("download payload has no text content")
    encoding = str(payload.get("encoding") or "").strip().lower()
    size = _coerce_size(payload.get("size"))
    if encoding in {"base64", "b64"}:
        if len(content) > (MAX_ATTACHMENT_BYTES * 4 // 3) + 8:
            raise _McpToolError(f"base64 body exceeds {MAX_ATTACHMENT_BYTES} bytes")
        raw = _decode_base64(content)
    elif encoding == "hex":
        if len(content) > MAX_ATTACHMENT_BYTES * 2 + 8:
            raise _McpToolError(f"hex body exceeds {MAX_ATTACHMENT_BYTES} bytes")
        try:
            raw = bytes.fromhex(content)
        except ValueError:
            raise _McpToolError("content is not valid hex") from None
    elif encoding in {"", "utf-8", "utf8", "text", "plain"}:
        raw = content.encode("utf-8", "surrogatepass")
    else:
        raise _McpToolError(f"unsupported encoding {encoding!r}")
    if not raw:
        raise _McpToolError("attachment is empty")
    if len(raw) > MAX_ATTACHMENT_BYTES:
        raise _McpToolError(f"attachment exceeds {MAX_ATTACHMENT_BYTES} bytes")
    if size is not None and len(raw) != size:
        raise _McpToolError(f"size mismatch (declared {size}, got {len(raw)})")
    return raw, size


def _decode_download(result: Mapping[str, Any]) -> tuple[bytes, int | None]:
    payload = _result_payload(result)
    if payload is not None and "content" in payload:
        return _decode_payload(payload)
    blocks = result.get("content")
    if not isinstance(blocks, list):
        raise _McpToolError("download response has no content")
    # A resource/blob block carries its own base64; that is structural, not a
    # guess about the string shape.
    for block in blocks:
        if not isinstance(block, dict) or block.get("type") != "resource":
            continue
        resource = block.get("resource")
        if isinstance(resource, dict) and isinstance(resource.get("blob"), str):
            raw = _decode_base64(resource["blob"])
            if not raw:
                raise _McpToolError("attachment is empty")
            if len(raw) > MAX_ATTACHMENT_BYTES:
                raise _McpToolError(f"attachment exceeds {MAX_ATTACHMENT_BYTES} bytes")
            return raw, None
    for block in blocks:
        if not isinstance(block, dict) or block.get("type") != "text":
            continue
        text = block.get("text")
        if not isinstance(text, str):
            continue
        encoding = str(block.get("encoding") or "").strip().lower()
        if encoding in {"base64", "b64"}:
            if len(text) > (MAX_ATTACHMENT_BYTES * 4 // 3) + 8:
                raise _McpToolError(f"base64 body exceeds {MAX_ATTACHMENT_BYTES} bytes")
            raw = _decode_base64(text)
        elif encoding in {"", "utf-8", "utf8", "text", "plain"}:
            raw = text.encode("utf-8", "surrogatepass")
        else:
            raise _McpToolError(f"unsupported encoding {encoding!r}")
        if not raw:
            raise _McpToolError("attachment is empty")
        if len(raw) > MAX_ATTACHMENT_BYTES:
            raise _McpToolError(f"attachment exceeds {MAX_ATTACHMENT_BYTES} bytes")
        return raw, None
    raise _McpToolError("download response has no usable content block")


def fetch_mcp(
    config: McpConfig | None,
    challenge_id: str,
    *,
    names: list[str] | None = None,
    should_skip: Callable[[str], bool] | None = None,
    deadline: float,
) -> ChannelResult:
    """List/download attachments through the platform MCP endpoint.

    ``names=None`` means "ask the server"; a list means "download these" and
    skips the listing call (the caller already has a listing from REST).
    """
    result = ChannelResult(channel="mcp")
    if config is None:
        result.errors.append("mcp channel disabled")
        return result
    session = _McpSession(config, deadline)
    specs: dict[str, FileSpec] = {}
    if names is None:
        try:
            listing_result = session.call_tool(
                "list_challenge_attachments", {"challenge_id": challenge_id}
            )
        except Exception as exc:  # noqa: BLE001 - channel failure is data
            result.errors.append(f"list {type(exc).__name__}: {_clip(exc)}")
            result.fatal = True
            return result
        if not isinstance(listing_result, dict) or listing_result.get("isError"):
            text = _text_of(listing_result if isinstance(listing_result, dict) else {})
            result.errors.append("list error: " + _clip(text or "isError"))
            result.fatal = True
            return result
        listing = _parse_mcp_listing(listing_result)
        if listing is None:
            result.errors.append("list returned an unrecognised payload")
            result.fatal = True
            return result
        result.listed = True
        result.files = listing
        # Keep the listed sizes: they are the only integrity check available
        # when the payload itself omits ``size``.
        specs = {spec.name: spec for spec in listing}
        names = [spec.name for spec in listing]

    for name in names:
        specs.setdefault(name, FileSpec(name=name))
    if not result.listed:
        result.files = list(specs.values())

    for raw_name, spec in specs.items():
        if _budget_spent(deadline):
            result.errors.append("budget spent before every file was fetched")
            break
        name = safe_attachment_name(raw_name)
        if name is None:
            result.errors.append(f"unsafe attachment name refused: {raw_name!r}")
            continue
        if should_skip is not None and should_skip(name):
            continue
        try:
            download = session.call_tool(
                "download_challenge_attachment",
                {"challenge_id": challenge_id, "filename": name},
            )
            if not isinstance(download, dict) or download.get("isError"):
                text = _text_of(download if isinstance(download, dict) else {})
                raise _McpToolError(text or "tool returned isError")
            blob, payload_size = _decode_download(download)
            if spec.size is not None and len(blob) != spec.size:
                raise _McpToolError(
                    f"size mismatch (listed {spec.size}, got {len(blob)})"
                )
            if payload_size is not None and len(blob) != payload_size:
                raise _McpToolError(
                    f"size mismatch (declared {payload_size}, got {len(blob)})"
                )
        except _McpHttpError as exc:
            result.errors.append(f"{name}: {_clip(exc)}")
            if exc.status in _MCP_AUTH_STATUS:
                result.fatal = True
                break
            continue
        except (TimeoutError, socket.timeout):
            result.errors.append(f"{name}: timeout")
            result.fatal = True
            break
        except _McpError as exc:
            result.errors.append(f"{name}: {_clip(exc)}")
            if isinstance(exc, _McpProtocolError):
                result.fatal = True
                break
            continue
        except Exception as exc:  # noqa: BLE001 - never break the caller
            result.errors.append(f"{name}: {type(exc).__name__}: {_clip(exc)}")
            if isinstance(exc, urllib.error.URLError):
                result.fatal = True
                break
            continue
        result.blobs[name] = blob
    return result
