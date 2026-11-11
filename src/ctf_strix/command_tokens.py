"""Shared tokenizer for shell commands carried by tool arguments.

Two guards parse the same text for different reasons:

* ``journey_guard`` asks "is this command a curl/wget session workflow?";
* ``restart_guard`` asks "which URLs did this shell command request?".

Both must first decode the tool's JSON argument (``{"command": ...}``) and
then tokenize it, because a string in a Python one-liner is not a command.
Keeping one implementation here means the two guards cannot drift apart on
quoting, path-prefixed executables, or option-value handling.

The tokenizer never executes anything; it only reads.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Final
from urllib.parse import urlsplit

#: One-sentence description used by the naming test. No ticket, IP, or path:
#: it must describe the capability, not the run that prompted it.
CHANGE_SUMMARY: Final[str] = (
    "HTTP client commands run through the shell feed the same deduplicated "
    "endpoint window as the probe ledger."
)

#: Executable names that speak HTTP from a shell.
_HTTP_CLIENTS: Final[frozenset[str]] = frozenset({"curl", "wget"})

#: Options whose *next* token is a value, not a URL.  The list is per client
#: because the same letter means different things (curl ``-O`` is a flag,
#: wget ``-O`` takes a file name).
_CURL_VALUE_OPTIONS: Final[frozenset[str]] = frozenset(
    {
        "-H", "--header", "-b", "--cookie", "-c", "--cookie-jar", "-d",
        "--data", "--data-raw", "--data-binary", "--data-urlencode",
        "-X", "--request", "-o", "--output", "-u", "--user", "-A",
        "--user-agent", "-e", "--referer", "-T", "--upload-file", "-F",
        "--form", "-m", "--max-time", "--connect-timeout", "-x", "--proxy",
        "--resolve", "--cacert", "--capath", "-E", "--cert", "--key",
        "--retry", "--retry-delay", "--retry-max-time", "--limit-rate",
        "--max-filesize", "-w", "--write-out", "-K", "--config",
    }
)
_WGET_VALUE_OPTIONS: Final[frozenset[str]] = frozenset(
    {
        "--header", "--load-cookies", "--save-cookies", "-O",
        "--output-document", "-o", "--output-file", "-P", "--directory-prefix",
        "-U", "--user-agent", "--user", "--password", "--post-data",
        "--post-file", "--body-data", "--body-file", "--method", "-e",
        "--execute", "-T", "--timeout", "-t", "--tries", "--limit-rate",
        "--wait", "--waitretry", "--ca-certificate", "--certificate",
        "--private-key", "-a", "--append-output", "-i", "--input-file",
        "-B", "--base", "-D", "--domains", "-A", "--accept", "-R",
        "--reject", "-I", "--include-directories", "-X", "--exclude-directories",
    }
)

#: Options whose value is itself a URL (so it must be extracted, not skipped).
_URL_VALUE_OPTIONS: Final[frozenset[str]] = frozenset({"--url", "--request-target"})

_URL_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_HOSTISH_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:localhost|\[[0-9A-Fa-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}|"
    r"[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})(?::\d+)?(?:[/?#]|$)"
)

_DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def command_text(args: str) -> str:
    """Return the shell text inside a tool's JSON arguments.

    Decoding first is what separates "ran curl" from "printed the word curl":
    ``python -c 'print("curl")'`` yields that whole one-liner, whose first
    token is ``python``, not ``curl``.
    """
    try:
        data = json.loads(args)
    except (TypeError, ValueError):
        return args
    if isinstance(data, dict):
        for key in ("command", "cmd", "script", "chars"):
            value = data.get(key)
            if isinstance(value, str):
                return value
    return args


def _split_raw_segments(text: str) -> list[str]:
    """Split on unquoted ``;``, ``&``, ``|`` and newlines.

    A quote-aware scan is required: query strings routinely contain ``&``
    inside a quoted URL, and splitting there would cut the URL in half.
    """
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            current.append(char)
            quote = char
            continue
        if char in ";&|\n":
            segments.append("".join(current))
            current = []
            continue
        current.append(char)
    segments.append("".join(current))
    return segments


def segments(text: str) -> list[list[str]]:
    """Tokenize each shell segment; malformed quoting falls back to split()."""
    out: list[list[str]] = []
    for raw in _split_raw_segments(text or ""):
        chunk = raw.strip().lstrip("(`").rstrip(")")
        if not chunk:
            continue
        try:
            tokens = shlex.split(chunk, posix=True)
        except ValueError:
            tokens = chunk.split()
        if tokens:
            out.append(tokens)
    return out


def _client_name(token: str) -> str | None:
    """Return ``curl``/``wget`` for a command word, else ``None``."""
    base = token.rsplit("/", 1)[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base if base in _HTTP_CLIENTS else None


def _looks_like_url(token: str) -> bool:
    if _URL_RE.match(token):
        return True
    return bool(_HOSTISH_RE.match(token))


def _urls_in_segment(tokens: list[str], client: str) -> list[str]:
    value_options = (
        _CURL_VALUE_OPTIONS if client == "curl" else _WGET_VALUE_OPTIONS
    )
    found: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            found.extend(t for t in tokens[index + 1:] if _looks_like_url(t))
            break
        if token.startswith("-") and token != "-":
            option, sep, attached = token.partition("=")
            if option in _URL_VALUE_OPTIONS:
                if sep and attached:
                    found.append(attached)
                elif index + 1 < len(tokens):
                    index += 1
                    found.append(tokens[index])
            elif option in value_options:
                if not sep and index + 1 < len(tokens):
                    index += 1
            index += 1
            continue
        if _looks_like_url(token):
            found.append(token)
        index += 1
    return found


def urls_in_command(text: str) -> list[str]:
    """Every URL argument of a curl/wget segment, in order, de-duplicated."""
    found: list[str] = []
    for tokens in segments(text):
        client = _client_name(tokens[0])
        if client is None:
            continue
        for url in _urls_in_segment(tokens, client):
            if url not in found:
                found.append(url)
    return found


def normalize_url(raw: str) -> tuple[str, str] | None:
    """Normalize a URL to ``(origin, path+query capped at 48 chars)``.

    ``origin`` is ``scheme://host`` plus a non-default port.  The default port
    is dropped so ``http://h/p`` and ``http://h:80/p`` are one endpoint.
    """
    text = (raw or "").strip()
    if not text:
        return None
    if "://" not in text:
        text = f"http://{text}"
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not host:
        return None
    origin = f"{scheme}://{host}"
    default_port = _DEFAULT_PORTS.get(scheme)
    if port is not None and port != default_port:
        origin = f"{origin}:{port}"
    suffix = parts.path or "/"
    if parts.query:
        suffix = f"{suffix}?{parts.query}"
    return origin, suffix[:48]


def endpoints_from_arguments(args: str) -> list[tuple[str, str]]:
    """Extract normalized endpoints from a shell tool's JSON arguments."""
    endpoints: list[tuple[str, str]] = []
    for url in urls_in_command(command_text(args)):
        normalized = normalize_url(url)
        if normalized is not None and normalized not in endpoints:
            endpoints.append(normalized)
    return endpoints