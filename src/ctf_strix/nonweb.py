"""Non-web primitives: decode chains, safe unpacking, hex view, raw TCP, ELF peek.

## Why these six and nothing else

The v2/v3 web surface answers "which request do I send next".  A rev/pwn/misc
challenge fails at a different place: the agent cannot see what it is holding.
EnIGMA (arXiv:2409.16165) reports the same split -- its gains came from
*interactive* tools that make each step observable (debugger, live socket),
not from adding one tool per challenge family.  NYU CTF Bench (arXiv:2406.05590)
adds the other half: failures cluster in multi-step composition, so the surface
must stay small and every call must return a decision, not a log dump.

So: one entry point per *question* the agent actually asks.

  * "what is this blob?"           -> decode_blob   (a chain, not one layer)
  * "what is inside this file?"    -> unpack_archive (recursive, budgeted)
  * "what are these bytes?"        -> hexpeek       (replaces xxd)
  * "what does this service say?"  -> tcp           (banner + one round trip)
  * "which of these inputs differ?"-> tcp_batch
  * "what is this binary?"         -> elfpeek

## Provenance (read before "improving" this by copying)

The reference pack lives in ``reference/pack-inspect-20261101/all-directions-pack-20261101``
(``tools-src/tools_misc_ext.py`` and ``tools_domain_ext.py``).  That pack ships
**no LICENSE file** -- verified by recursive search.  This module is therefore
an independent implementation written against observed behaviour, not a port:
same user-visible contract, own code, own comments.  Do not paste code from the
pack in here.

## Registration cost

``FILE_TOOLS`` and ``TCP_TOOLS`` register separately, because a file-only
challenge should not pay schema tokens for a socket tool and vice versa.  The
six schemas are ~2.5k chars; paying them on a web challenge is pure waste
(measured: 17 bookkeeping schemas cost 4.2k chars for zero calls).
"""

from __future__ import annotations

import base64
import bz2
import codecs
import errno
import gzip
import heapq
import html
import io
import itertools
import lzma
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import tarfile
import time
import zipfile
import zlib
from pathlib import Path
from typing import Final
from urllib.parse import unquote

from ctf_strix.flag_extract import FLAG_RE
from ctf_strix.file_triage import resolve_path

#: 与 ``flag_extract.FLAG_RE`` 同一对象（标签式前缀，不是 FLAG/CTF 白名单）。
#: 原来这里是一份字面量副本，理由是"模块可独立导入、无循环依赖"——实测代价
#: 是两份前缀各自漂移，解码链在一处认得出 flag、在另一处认不出。``flag_extract``
#: 只依赖标准库，导入它不会成环。
_FLAG_RE: Final = FLAG_RE

#: A 10MB "blob" is a file, not a blob.  Saying so costs one line instead of
#: 256k characters of garbage in the context.
_BLOB_MAX_CHARS: Final = 256 * 1024
#: Five independent encodings is already unusual; more means the scoring is
#: chasing its own tail.
_BLOB_MAX_LAYERS: Final = 8

#: Bounded best-first search over decode candidates.  A single greedy pick per
#: layer ends the chain on the first wrong winner, and the printable gate alone
#: cannot tell a real next layer from noise that happened to decode.  Three
#: runner-ups per state plus a hard node/time budget keeps the search honest
#: without letting an adversarial blob hang the tool.
_SEARCH_MAX_NODES: Final = 240
_SEARCH_BREADTH: Final = 3
_SEARCH_SECONDS: Final = 5.0
_SEARCH_GATE: Final = 0.85
#: Inflate budget for one embedded gzip/zlib layer.  A 256 KB blob cannot
#: honestly expand past a few MB; anything beyond that is a bomb.
_BLOB_INFLATE_MAX: Final = 4 * 1024 * 1024
#: Base58 (Bitcoin alphabet) is O(n^2) in Python ints; CTF blobs are short and
#: a long input is never base58, so refuse instead of burning seconds.
_B58_MAX_CHARS: Final = 4096
_B58_ALPHA: Final = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_RE: Final = re.compile(r"[1-9A-HJ-NP-Za-km-z]+")
_UNICODE_ESC_RE: Final = re.compile(r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\x[0-9a-fA-F]{2}")
_ROT47_TABLE: Final = str.maketrans(
    {code: 33 + (code - 33 + 47) % 94 for code in range(33, 127)}
)

#: Formats ``_sniff`` can name but this module has no stdlib reader for.
#: Both are extracted with the system 7z binary when present (``_from_7z``);
#: this set only decides what to say when that binary is missing, and which
#: ``kind`` values must never reach the stdlib dispatch (it would raise
#: ``KeyError`` on the opener table).  Debian's ``p7zip-full`` is 7-Zip
#: proper and does read RAR/RAR5 -- verified end to end (FMT-5), so RAR no
#: longer belongs in the "never extracts" category, only in "needs 7z".
_BINARY_ONLY: Final = frozenset({"7z", "rar"})

#: Extraction budget, shared across recursion depth.  Without sharing, five
#: levels of "64MB each" is 320MB on a 3GB VM -- the bomb wins by arithmetic.
_UNPACK_MAX_BYTES: Final = 64 * 1024 * 1024
_UNPACK_MAX_FILES: Final = 2000
#: Uncompressed-size gate for one member, checked before reading.
_UNPACK_MEMBER_MAX: Final = 64 * 1024 * 1024

#: One screen is enough to recognise a header; more is a file.
_HEX_MAX: Final = 1024
_HEX_WIDTH: Final = 16

#: tcp_batch is a one-shot comparison, not a fuzzer.  200 candidates covers
#: padding-oracle work and stays inside one tool timeout.
_BATCH_MAX: Final = 200

_PRINTABLE: Final = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

_ENGLISH_RE: Final = re.compile(
    r"\b(the|and|you|this|that|with|login|admin|password|username|token|flag|ctf"
    r"|http|select|database|secret|encrypt|decrypt|script|query|session|cookie"
    r"|config|function|return|error|success|welcome|system|bash|hello|world"
    r"|answer|message|plain|cipher|layer|content|value|name|file|text)\b"
)


class _NonWebError(Exception):
    """An error a model can act on; never surfaced as a traceback."""


# --- 截断必须自己说出来（报告 PWN-4） ----------------------------------------
#
# 这条链路上有四处静默截断：socket 层 `_drain` 读满 cap 就停、`_render` 只印
# 前 256/600 B、`tcp_batch` 每行只印前 48 B、`_clip` 砍到 4000 字符。
#
# 代价不是"少看几个字节"，而是**把截断伪装成结论**：一个 1100 B 的响应只印
# 前 600 B，读到的结尾和"响应就到这里"长得一模一样；而按字节泄漏的 oracle
# 判别位常在尾部，于是"每一行都一样"变成了一个看起来有证据的错误结论。
#
# 约定：每处截断都报出截了多少、从哪个 offset 开始、去哪里读回。落盘根沿用
# `traffic._default_path` 的既有约定（CWD，可用环境变量覆盖/关闭），不引入
# 新的路径根；回读走已有的 `hexpeek(path, offset, length)` / `read_file`。
_CLIP_DEFAULT: Final = 4000
_TCP_DUMP_ENV: Final = "CTF_TCP_DUMP_DIR"
_RENDER_ASCII_HEAD: Final = 600
_RENDER_ASCII_TAIL: Final = 200
_RENDER_HEX_HEAD: Final = 256
_RENDER_HEX_TAIL: Final = 64
_ROW_EDGE: Final = 24
_ROW_FULL: Final = 2 * _ROW_EDGE


def _dump_root() -> Path | None:
    """Directory for response dumps, or ``None`` when disabled/unwritable."""
    raw = os.environ.get(_TCP_DUMP_ENV, "").strip()
    if raw.lower() in ("off", "0", "none"):
        return None
    root = resolve_path(raw or "tcpdump")
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return root


def _dump(data: bytes | str, tag: str) -> str:
    """Write ``data`` somewhere the model can read it back by offset.

    Returns the path, or "" when nothing could be written.  Callers must then
    say the full body was NOT stored -- printing a path that does not exist is
    worse than printing no path, because the model will spend a turn on it.
    """
    root = _dump_root()
    if root is None:
        return ""
    suffix = ".bin" if isinstance(data, bytes) else ".txt"
    name = f"{tag}-{os.getpid()}-{time.time_ns()}{suffix}"
    path = root / name
    try:
        payload = data if isinstance(data, bytes) else data.encode("utf-8", "surrogateescape")
        tmp = path.with_name(name + ".tmp")
        tmp.write_bytes(payload)
        os.replace(tmp, path)
    except OSError:
        return ""
    return str(path)


def _clip(text: str, limit: int = _CLIP_DEFAULT) -> str:
    """Truncate a tool result, but never in the middle of a flag.

    A truncated flag is indistinguishable from a wrong answer downstream, and
    the log hook has physically cut one before (old ledger defect #6), so when
    a flag is present the window widens to cover it.
    """
    if len(text) <= limit:
        return text
    match = _FLAG_RE.search(text)
    if match and match.end() > limit:
        limit = min(match.end() + 64, len(text))
    if len(text) <= limit:
        return text
    return text[: limit - 60] + f"\n...[truncated, {len(text)} chars total]"


def _ratio(data: bytes) -> float:
    """Share of bytes that are printable ASCII (incl. CR/LF/TAB)."""
    if not data:
        return 0.0
    return sum(1 for byte in data if byte in _PRINTABLE) / len(data)


def _english_hint(text: str) -> int:
    """Count of distinct English-ish words; used to judge a rot13 candidate."""
    return len(set(_ENGLISH_RE.findall(text.lower())))


def _to_int(value: object, default: int, low: int, high: int) -> int:
    """Parse an int argument from a model, clamped; garbage falls back.

    Tool arguments arrive as strings often enough that ``int()`` raising here
    used to kill a whole turn.
    """
    if value is None or str(value).strip() == "":
        return default
    try:
        number = int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return default
    return max(low, min(number, high))


# ---------------------------------------------------------------------------
# 1. decode_blob -- a chain, not a single guess
# ---------------------------------------------------------------------------


def _as_b64(text: str) -> bytes | None:
    compact = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
    if len(compact) < 8:
        return None
    compact += "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(compact, validate=False)
    except (ValueError, TypeError):
        return None
    # Round-trip check: with sloppy padding almost any input decodes to
    # *something*, and that something poisons the next layer.
    if base64.b64encode(raw).decode().rstrip("=") != compact.rstrip("="):
        return None
    return raw


def _as_b32(text: str) -> bytes | None:
    compact = re.sub(r"\s+", "", text).upper()
    if len(compact) < 8:
        return None
    compact += "=" * (-len(compact) % 8)
    try:
        raw = base64.b32decode(compact, casefold=True)
    except (ValueError, TypeError):
        return None
    if base64.b32encode(raw).decode().rstrip("=") != compact.rstrip("="):
        return None
    return raw


def _as_hex(text: str) -> bytes | None:
    stripped = re.sub(r"0x", "", text, flags=re.I)
    stripped = re.sub(r"\\x", "", stripped, flags=re.I)
    stripped = re.sub(r"[\s,;:\-]", "", stripped)
    if len(stripped) < 8 or len(stripped) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return None
    try:
        return bytes.fromhex(stripped)
    except ValueError:
        return None


def _as_binary(text: str) -> bytes | None:
    bare = re.sub(r"\s", "", text)
    bits = re.sub(r"[^01]", "", text)
    if len(bits) < 16 or len(bits) % 8:
        return None
    # Reject prose that merely contains 0/1 characters.
    if len(bits) / max(1, len(bare)) < 0.9:
        return None
    return bytes(int(bits[index : index + 8], 2) for index in range(0, len(bits), 8))


def _b58_encode(raw: bytes) -> str:
    """Bitcoin-alphabet base58, only used to round-trip a decoded candidate."""
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    number = int.from_bytes(raw, "big")
    digits: list[str] = []
    while number:
        number, remainder = divmod(number, 58)
        digits.append(_B58_ALPHA[remainder])
    return "1" * pad + "".join(reversed(digits))


def _as_b58(text: str) -> bytes | None:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 8 or len(compact) > _B58_MAX_CHARS or not _B58_RE.fullmatch(compact):
        return None
    number = 0
    for char in compact:
        number = number * 58 + _B58_ALPHA.index(char)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    raw = b"\x00" * (len(compact) - len(compact.lstrip("1"))) + body
    # Same reason as base64: almost any string is a number, and a bogus layer
    # poisons every later step.
    if _b58_encode(raw) != compact:
        return None
    return raw or None


def _as_b85(text: str) -> bytes | None:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 8:
        return None
    try:
        raw = base64.b85decode(compact)
    except (ValueError, TypeError):
        return None
    if base64.b85encode(raw).decode() != compact:
        return None
    return raw or None


def _as_a85(text: str) -> bytes | None:
    """Adobe ASCII85; only accepted inside its ``<~ ... ~>`` delimiters."""
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 10 or not compact.startswith("<~") or not compact.endswith("~>"):
        return None
    body = compact[2:-2]
    try:
        raw = base64.a85decode(body)
    except (ValueError, TypeError):
        return None
    if base64.a85encode(raw).decode() != body:
        return None
    return raw or None


def _rot47(text: str) -> str:
    """ROT47 is the 94-character printable rotation; it also flips digits."""
    return text.translate(_ROT47_TABLE)


def _as_unicode_escapes(text: str) -> str | None:
    """Turn literal ``\\uXXXX`` / ``\\xNN`` escapes back into characters."""
    if not text.isascii() or len(_UNICODE_ESC_RE.findall(text)) < 2:
        return None
    try:
        decoded = codecs.decode(text, "unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return None
    if decoded == text:
        return None
    # ``unicode_escape`` maps each byte to one codepoint; step back through
    # latin-1 so a ``\\xe4\\xb8\\xad`` sequence becomes the UTF-8 character it
    # was in the original file.
    try:
        return decoded.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return decoded


def _inflate(raw: bytes) -> tuple[bytes, str] | None:
    """Unwrap one gzip or zlib layer; ``None`` when the bytes are neither."""
    if raw.startswith(b"\x1f\x8b"):
        wbits, codec = 16 + zlib.MAX_WBITS, "gzip"
    elif len(raw) > 2 and raw[0] == 0x78 and raw[1] in (0x01, 0x5E, 0x9C, 0xDA):
        wbits, codec = zlib.MAX_WBITS, "zlib"
    else:
        return None
    try:
        engine = zlib.decompressobj(wbits)
        payload = engine.decompress(raw, _BLOB_INFLATE_MAX)
    except zlib.error:
        return None
    # A truncated or bomb-sized stream is not a layer; keep the raw bytes so
    # the caller still reports what it actually decoded.
    if not engine.eof or engine.unconsumed_tail:
        return None
    return payload, codec


def _bytes_to_text(raw: bytes) -> tuple[str, tuple[str, ...], float]:
    """Decode one layer of bytes to text, inflating and de-wide-charing first.

    Returns ``(text, extra step names, printable ratio)``.  The ratio is always
    measured on the bytes *after* inflation: measuring it on a latin-1 rescue
    string would be 1.0 for arbitrary binary and let noise through the 0.85
    gate.
    """
    extra: tuple[str, ...] = ()
    inflated = _inflate(raw)
    if inflated is not None:
        raw, codec = inflated
        extra = (codec,)
    # UTF-16 text is half NUL bytes and ASCII-valid, so it never raises; catch it
    # before the utf-8 branch.  The ratio is per character (the wide bytes would
    # score ~0.5 no matter how readable the text is).
    if len(raw) % 2 == 0 and len(raw) >= 8 and raw.count(b"\x00") >= len(raw) // 4:
        for order in ("utf-16-le", "utf-16-be"):
            try:
                text = raw.decode(order)
            except UnicodeDecodeError:
                continue
            ratio = sum(
                1 for char in text if char.isprintable() or char in "\t\n\r"
            ) / len(text)
            if ratio >= _SEARCH_GATE or _FLAG_RE.search(text):
                return text, extra + (order,), ratio
    try:
        return raw.decode("utf-8"), extra, _ratio(raw)
    except UnicodeDecodeError:
        pass
    return raw.decode("latin-1"), extra, _ratio(raw)


def _text_variants(text: str) -> list[tuple[str, str]]:
    """Transforms that keep text as text (no encoding layer)."""
    out: list[tuple[str, str]] = []
    rot = codecs.encode(text, "rot13")
    # rot13/rot47 are bijections on their alphabets, so they always "succeed";
    # accept one only when it produces a flag or more English than the input.
    # Without this gate a plain sentence gets "decoded" into nonsense and the
    # chain records a step that made the text worse.
    if rot != text and (_FLAG_RE.search(rot) or _english_hint(rot) > _english_hint(text)):
        out.append(("rot13", rot))
    rot47 = _rot47(text)
    if rot47 != text and (
        _FLAG_RE.search(rot47) or _english_hint(rot47) > _english_hint(text)
    ):
        out.append(("rot47", rot47))
    url = unquote(text)
    if url != text:
        out.append(("urlencode", url))
    entity = html.unescape(text)
    if entity != text:
        out.append(("html-entity", entity))
    escapes = _as_unicode_escapes(text)
    if escapes is not None:
        out.append(("unicode-escape", escapes))
    return out


def _decode_candidates(text: str) -> list[tuple[str, str, float]]:
    """Return ``(step name, decoded text, score)`` for plausible decodings.

    Score = printable ratio plus 0.5 for containing a flag.  The 0.85 gate at
    the call site is what stops the chain from "decoding" arbitrary prose.
    Byte decoders may contribute more than one step name (``hex+zlib``).
    """
    found: list[tuple[str, str, float]] = []
    for name, func in (
        ("base64", _as_b64),
        ("base32", _as_b32),
        ("base58", _as_b58),
        ("base85", _as_b85),
        ("ascii85", _as_a85),
        ("hex", _as_hex),
        ("binary", _as_binary),
    ):
        raw = func(text)
        if raw is None:
            continue
        decoded, extra, ratio = _bytes_to_text(raw)
        hit = bool(_FLAG_RE.search(decoded))
        if ratio >= _SEARCH_GATE or hit:
            found.append(("+".join((name, *extra)), decoded, ratio + (0.5 if hit else 0.0)))
    for name, decoded in _text_variants(text):
        hit = bool(_FLAG_RE.search(decoded))
        found.append((
            name,
            decoded,
            _ratio(decoded.encode("utf-8", "replace")) + (0.5 if hit else 0.0),
        ))
    return found


def _as_b64_lenient(text: str) -> bytes | None:
    """Base64 decode that tolerates a mangled final character.

    The strict decoder round-trips the input because "almost any bytes decode
    to something".  That gate is right for a *chain*: a bogus layer poisons
    every later step.  It is wrong for base64 **steganography**, where the
    last character of each line is deliberately non-canonical -- the payload
    lives exactly in those bits.  Measured on a real misc attachment: 60 of 81
    lines were rejected by the strict decoder, all of them differing only at
    index -1.

    Only the final partial group is allowed to differ; a mismatch anywhere
    earlier means the line is genuinely not base64.
    """
    compact = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
    if len(compact) < 8 or not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return None
    padded = compact + "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (ValueError, TypeError):
        return None
    reencoded = base64.b64encode(raw).decode().rstrip("=")
    target = padded.rstrip("=")
    if reencoded == target:
        return raw
    # Tolerate a difference confined to the last character (the last 6-bit
    # group covers only the high bits of the final byte; the low bits are
    # padding and are what stego rewrites).
    if len(reencoded) == len(target) and reencoded[:-1] == target[:-1]:
        return raw
    return None


_B64_ALPHA: Final = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _b64_stego_bits(lines: list[str]) -> tuple[str, int] | None:
    """Recover payload bits hidden in base64 padding characters.

    In base64 steganography the canonical encoder fills the unused low bits of
    the final group with zeros; a stego encoder instead puts payload bits
    there.  Each trailing ``=`` marks how many bits are spare: two pads = 4
    free bits, one pad = 2.

    Measured on a real challenge (``encode__base64-stego``): decoding the last
    character of every line yields ``n35...`` and the answer is one ASCII
    character per four bits, MSB first.  Because the padding is the *only*
    thing that changes, this is invisible to any plain "decode the base64"
    approach -- the decoded text looks like ordinary English.

    Returns:
        ``(decoded payload text, bits consumed)`` or None when the file does
        not look like padded base64 lines.
    """
    padded = [line.rstrip() for line in lines if line.rstrip().endswith("=")]
    if len(padded) < 4 or len(padded) / len(lines) < 0.5:
        return None
    bits: list[str] = []
    for line in padded:
        pad = len(line) - len(line.rstrip("="))
        if pad not in (1, 2):
            continue
        last = line.rstrip("=")[-1:]
        if not last or last not in _B64_ALPHA:
            continue
        value = _B64_ALPHA.index(last)
        if pad == 2:
            # 4 spare bits: the low 4 of the 6-bit group
            bits.append(format(value & 0x0F, "04b"))
        else:
            # 2 spare bits: the low 2
            bits.append(format(value & 0x03, "02b"))
    joined = "".join(bits)
    if len(joined) < 8:
        return None
    payload = bytes(
        int(joined[index : index + 8], 2) for index in range(0, len(joined) - 7, 8)
    )
    text = payload.decode("latin-1", "replace")
    if _FLAG_RE.search(text) or _ratio(payload) >= 0.9:
        return text, len(joined)
    return None


def _decode_linewise(text: str) -> tuple[str, int, int] | None:
    """Decode a blob whose *lines* are separately encoded.

    Measured on a real misc attachment: 81 lines, each a complete base64
    string, so the whole file is not a valid base64 stream (the newlines and
    per-line padding break the round-trip check).  Treating the file as one
    blob therefore reports "no chain" on a file that decodes cleanly line by
    line -- the model then concludes the file is encrypted.

    Only used as a fallback after whole-text decoding fails, and only when at
    least two lines decode to mostly printable text; otherwise ordinary prose
    would be "decoded" one sentence at a time.

    Returns:
        ``(joined text, decoded line count, total non-empty lines)`` or None.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return None
    decoded: list[str] = []
    for line in lines:
        candidates = _decode_candidates(line)
        best = max(candidates, key=lambda item: item[2], default=None)
        if best is None or best[2] < 0.85:
            raw = _as_b64_lenient(line)
            if raw is None:
                decoded.append("")
                continue
            text_value = raw.decode("latin-1", "replace")
            if _ratio(raw) < 0.85:
                decoded.append("")
                continue
            decoded.append(text_value)
            continue
        decoded.append(best[1])
    count = sum(1 for item in decoded if item)
    if count < 2 or count / len(lines) < 0.6:
        return None
    return "\n".join(item for item in decoded if item), count, len(lines)


def decode_blob(text: str = "", max_layers: int = 5) -> str:
    """Decode a multi-layer encoded string and report the chain that worked.

    Handles base64 / base32 / base58 / base85 / ascii85 / hex / binary, one
    gzip or zlib layer and UTF-16 between layers, plus rot13 / rot47 /
    urlencode / html-entity / unicode-escape text transforms.

    Candidates are explored best-first with up to three runner-ups per state
    instead of a single greedy pick: one wrong winner used to end the chain,
    and the 0.85 printable gate alone cannot tell "a real next layer" from
    "noise that happened to decode".  The search is bounded (240 states, 5 s),
    so an adversarial blob cannot hang the tool.

    Args:
        text: The blob or encoded string (file content, pasted token, etc.).
        max_layers: How many nested encodings to peel, 1-8, default 5.

    Returns:
        The chain (``base64 -> hex``), the flag if one appeared, the first 200
        chars of the result, one line per layer so a wrong turn is visible, and
        the runner-up branches that also decoded.
    """
    if not isinstance(text, str) or not text.strip():
        return (
            "[decode_blob] text is empty. Paste the blob, or for a file run "
            "hexpeek(path) first to confirm the bytes are what you think."
        )
    if len(text) > _BLOB_MAX_CHARS:
        return _clip(
            f"[decode_blob] input is {len(text)} chars, over the {_BLOB_MAX_CHARS} "
            "limit. This is a file, not a blob: read its header with hexpeek, "
            "or decode only the relevant segment."
        )

    layers = _to_int(max_layers, 5, 1, _BLOB_MAX_LAYERS)
    current = text.strip()

    counter = itertools.count()
    # (priority, depth, tie-break, chain, steps, text).  Every state scores at
    # most 1.5, so the root sits at -1.0 and is always expanded first.
    heap: list[tuple[float, int, int, tuple[str, ...], tuple[str, ...], str]] = [
        (-1.0, 0, next(counter), (), (), current)
    ]
    seen = {current}
    # Runner-up candidates, keyed by the chain that produced them, so the
    # report can say "at L2 'hex' instead of 'base64' led to ...".
    alts: dict[tuple[str, ...], list[tuple[str, str]]] = {}
    best: tuple[int, float, tuple[str, ...], tuple[str, ...], str] | None = None
    hit = ""
    expanded = 0
    branches = 0
    note = ""
    started = time.monotonic()

    while heap:
        _, depth, _, chain, steps, current = heapq.heappop(heap)
        if depth >= layers:
            continue
        if expanded >= _SEARCH_MAX_NODES:
            note = f"node budget of {_SEARCH_MAX_NODES} state(s) reached"
            break
        if time.monotonic() - started > _SEARCH_SECONDS:
            note = f"time budget of {_SEARCH_SECONDS:.0f}s reached"
            break
        expanded += 1

        candidates = [
            item for item in _decode_candidates(current) if item[2] >= _SEARCH_GATE
        ]
        candidates.sort(key=lambda item: (-item[2], item[0]))
        candidates = candidates[:_SEARCH_BREADTH]
        if len(candidates) > 1:
            alts[chain] = [(name, decoded) for name, decoded, _ in candidates[1:]]
        for name, decoded, score in candidates:
            next_text = decoded.strip()
            if not next_text or next_text in seen:
                continue
            seen.add(next_text)
            branches += 1
            next_chain = chain + (name,)
            next_steps = steps + (f"L{depth + 1} {name} -> {decoded[:80]!r}",)
            # Prefer the deepest chain, then the best score: the old greedy
            # walk also followed decoding as far as it went.
            if best is None or (depth + 1, score) > (best[0], best[1]):
                best = (depth + 1, score, next_chain, next_steps, next_text)
            match = _FLAG_RE.search(next_text)
            if match:
                hit = match.group(0)
                best = (depth + 1, score, next_chain, next_steps, next_text)
                heap.clear()
                break
            heapq.heappush(
                heap,
                (-score, depth + 1, next(counter), next_chain, next_steps, next_text),
            )
        if hit:
            break

    chain: tuple[str, ...] = ()
    steps: tuple[str, ...] = ()
    current = text.strip()
    if best is not None:
        _, _, chain, steps, current = best

    if not chain:
        stego = _b64_stego_bits([line for line in text.strip().splitlines() if line.strip()])
        if stego is not None:
            payload_text, used = stego
            parts = [
                f"[decode_blob] base64 padding steganography: {used} payload bits "
                "recovered from the padding characters of the last group",
                f"result (first 200 chars):\n{payload_text[:200]}",
            ]
            hit = _FLAG_RE.search(payload_text)
            if hit:
                parts.insert(0, f"[decode_blob] flag: {hit.group(0)}")
            return _clip("\n\n".join(parts))

        blocks = _decode_linewise(current)
        if blocks is not None:
            joined, decoded_count, total = blocks
            parts = [
                f"[decode_blob] the blob is {total} separately encoded lines "
                f"({decoded_count} decoded); whole-text decoding fails because "
                "the layers are per-line, not one stream",
                f"result (first 200 chars):\n{joined[:200]}",
            ]
            hit = _FLAG_RE.search(joined)
            if hit:
                parts.insert(0, f"[decode_blob] flag: {hit.group(0)}")
            else:
                parts.append(
                    "next: the lines decode but the answer is not in the plain "
                    "text -- compare the lines against each other (the "
                    "difference between near-identical lines is the payload)."
                )
            return _clip("\n\n".join(parts))

        return _clip(
            "[decode_blob] no decoding chain recognised.\n"
            "next: confirm the blob was not truncated (copy the whole token), "
            "then check the raw bytes with hexpeek -- if entropy is high and "
            "nothing decodes, it is compressed or encrypted, not encoded."
        )

    parts = [f"[decode_blob] chain: {' -> '.join(chain)} ({len(chain)} layer(s))"]
    if hit:
        parts.append(f"flag: {hit}")
    parts.append(f"result (first 200 chars):\n{current[:200]}")
    parts.append("per-layer:\n" + "\n".join(steps))
    parts.append(
        f"search: {expanded} state(s) expanded, {branches} branch(es) decoded"
        + (f"; {note}" if note else "")
    )
    if not hit:
        alternatives: list[str] = []
        for index, chosen in enumerate(chain):
            for name, decoded in alts.get(chain[:index], []):
                alternatives.append(
                    f"L{index + 1} '{name}' instead of '{chosen}' led to "
                    f"{decoded[:60]!r}"
                )
        if alternatives:
            parts.append(
                "other branches that decoded (a wrong top pick is the usual "
                "failure):\n" + "\n".join(alternatives[:4])
            )
        else:
            parts.append(
                "next: no flag yet, and no other branch decoded at any layer -- "
                "if the result is short and unreadable, raise max_layers; if it "
                "is readable text, the payload is behind a cipher or a different "
                "alphabet, not another encoding layer."
            )
    return _clip("\n\n".join(parts))


# ---------------------------------------------------------------------------
# 2. unpack_archive -- magic sniffing + a shared budget
# ---------------------------------------------------------------------------


def _sniff(path: Path) -> str:
    """Identify an archive by magic bytes; extension is not evidence."""
    try:
        # 64 KB, not 512 B: a RAR self-extracting stub legally precedes the
        # signature by up to that much, and reading less makes such a file
        # indistinguishable from an unknown blob.
        with path.open("rb") as handle:
            head = handle.read(64 * 1024)
    except OSError:
        return ""
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    # Zstandard frame magic.  ``zstandard`` ships in the image's dependency
    # closure already (pwntools pulls it in); the frame was simply never
    # named, so a .zst looked like an unknown blob.  No CLI is installed and
    # 7z has no Zstd codec, so this is the only reader.
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    # 7z and RAR are *named* before any extraction attempt: Python's stdlib
    # has no reader for either.  walk() hands both to the system 7z binary
    # when it exists; naming matters because "detected unknown, nothing
    # extracted" reads exactly like a corrupt file -- the model then retries
    # unpack_archive instead of changing method.  A RAR self-extracting stub
    # can precede the signature by up to 64 KB (rarlab technote), so search
    # that window rather than byte 0.
    window = head[: 64 * 1024]
    if window.find(b"\x37\x7a\xbc\xaf\x27\x1c") >= 0:
        return "7z"
    if window.find(b"Rar!\x1a\x07") >= 0:
        return "rar"
    return ""


class _Sink:
    """Write members under ``root`` while enforcing four escape gates.

    The gates exist because CTF attachments are hostile by construction:
    ``../../flag`` inside a zip is a normal Tuesday.  ``budget`` is shared
    across recursion so nested archives cannot multiply the limit.
    """

    def __init__(self, root: Path, budget: dict[str, int]) -> None:
        self.root = root.resolve()
        self.budget = budget
        self.skipped: list[str] = []

    def accept(self, member: str) -> Path | None:
        name = (member or "").replace("\\", "/")
        if not name or name.endswith("/"):
            return None
        if name.startswith("/") or re.match(r"^[A-Za-z]:/", name):
            self.skipped.append(f"{member}: absolute path")
            return None
        if ".." in Path(name).parts:
            self.skipped.append(f"{member}: '..' segment")
            return None
        target = (self.root / name).resolve()
        if not target.is_relative_to(self.root):
            self.skipped.append(f"{member}: escapes root (zip slip)")
            return None
        if self.budget["files"] >= _UNPACK_MAX_FILES:
            self.skipped.append(f"{member}: file budget {_UNPACK_MAX_FILES} reached")
            return None
        return target

    def write(self, target: Path, data: bytes) -> bool:
        if self.budget["bytes"] + len(data) > _UNPACK_MAX_BYTES:
            self.skipped.append(
                f"{target.name}: total budget {_UNPACK_MAX_BYTES // 1048576}MB reached"
            )
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        self.budget["bytes"] += len(data)
        self.budget["files"] += 1
        return True


def _open_zip(path: Path):
    """Open a zip even when data is appended after the end-of-central-directory.

    Measured on a real misc attachment (``1.zip``, 145,914 B): the EOCD sits at
    offset 2,379 and 143,535 bytes of unrelated data follow it.  That is a
    polyglot/overlay, not corruption, and ``zipfile`` refuses it outright
    (``BadZipFile: File is not a zip file``) because it only scans the last
    64KB for the EOCD.

    Fallback: find the first EOCD, cut the file there, and open that.  The
    central-directory offsets are relative to the file start, so the prefix is
    still a valid archive.  Returns ``(archive, note)``; ``note`` explains the
    truncation so it is visible in the tool output instead of silent.
    """
    try:
        return zipfile.ZipFile(path), ""
    except zipfile.BadZipFile:
        raw = path.read_bytes()
        marker = raw.find(b"PK\x05\x06")
        if marker < 0:
            raise
        comment_len = int.from_bytes(raw[marker + 20 : marker + 22], "little")
        end = marker + 22 + comment_len
        if end > len(raw):
            raise
        note = (
            f"{len(raw) - end} bytes after the zip end-of-central-directory were "
            "ignored (overlay/polyglot); the archive itself is intact"
        )
        return zipfile.ZipFile(io.BytesIO(raw[:end])), note


def _from_zip(path: Path, sink: _Sink) -> None:
    archive, note = _open_zip(path)
    if note:
        sink.skipped.append(f"{path.name}: {note}")
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                # Encrypted entry: zipfile raises RuntimeError on read.  Report
                # "password-protected" (itself a misc-challenge hint) instead of
                # crashing the turn.
                sink.skipped.append(f"{info.filename}: encrypted entry")
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                sink.skipped.append(f"{info.filename}: symlink")
                continue
            if info.file_size > _UNPACK_MEMBER_MAX:
                sink.skipped.append(f"{info.filename}: declared size over member limit")
                continue
            target = sink.accept(info.filename)
            if target is None:
                continue
            # Read one byte past the limit: a lying header then costs 64MB+1,
            # not the whole disk.
            with archive.open(info) as handle:
                data = handle.read(_UNPACK_MEMBER_MAX + 1)
            if len(data) > _UNPACK_MEMBER_MAX:
                sink.skipped.append(f"{info.filename}: actual size over limit")
                continue
            sink.write(target, data)


def _from_tar(path: Path, sink: _Sink) -> None:
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if member.issym() or member.islnk():
                sink.skipped.append(f"{member.name}: link member")
                continue
            if not member.isfile():
                continue
            if member.size > _UNPACK_MEMBER_MAX:
                sink.skipped.append(f"{member.name}: declared size over member limit")
                continue
            target = sink.accept(member.name)
            if target is None:
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            data = handle.read(_UNPACK_MEMBER_MAX + 1)
            if len(data) > _UNPACK_MEMBER_MAX:
                sink.skipped.append(f"{member.name}: actual size over limit")
                continue
            sink.write(target, data)


def _from_stream(path: Path, kind: str, sink: _Sink) -> None:
    opener = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}[kind]
    name = path.stem if path.suffix in {".gz", ".bz2", ".xz"} else path.name + ".out"
    target = sink.accept(name)
    if target is None:
        return
    try:
        with opener(path, "rb") as handle:
            data = handle.read(_UNPACK_MEMBER_MAX + 1)
    except (OSError, EOFError, lzma.LZMAError):
        sink.skipped.append(f"{name}: decompression failed")
        return
    if len(data) > _UNPACK_MEMBER_MAX:
        sink.skipped.append(f"{name}: actual size over limit")
        return
    sink.write(target, data)


def _zstd_name(path: Path) -> str:
    """``x.tar.zst`` -> ``x.tar`` so the next walk level still sees a tar."""
    name = path.name
    for suffix in (".zstd", ".zst"):
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    if name.endswith(".tzst") and len(name) > len(".tzst"):
        return name[: -len(".tzst")] + ".tar"
    return name + ".out"


def _from_zstd(path: Path, sink: _Sink) -> None:
    """Decompress a Zstandard frame; the magic makes the format certain.

    ``zstandard`` is already in the image's dependency closure, so this is a
    wiring fix rather than a new dependency -- but the import stays lazy and
    failure becomes a reported skip, because a host without the wheel must
    still get an accurate "no reader" line instead of an empty directory.
    """
    try:
        import zstandard
    except ImportError:  # pragma: no cover - exercised by monkeypatching sys.modules
        sink.skipped.append(f"{path.name}: zstandard is not installed")
        return
    name = _zstd_name(path)
    target = sink.accept(name)
    if target is None:
        return
    try:
        with path.open("rb") as raw:
            reader = zstandard.ZstdDecompressor().stream_reader(raw)
            with reader:
                data = reader.read(_UNPACK_MEMBER_MAX + 1)
    except (OSError, zstandard.ZstdError):
        sink.skipped.append(f"{name}: decompression failed")
        return
    if len(data) > _UNPACK_MEMBER_MAX:
        sink.skipped.append(f"{name}: actual size over limit")
        return
    sink.write(target, data)


def _from_7z(path: Path, sub: Path, budget: dict[str, int]) -> list[str]:
    """Extract with the system 7z binary, then enforce the same gates.

    The binary writes files itself, so the pre-write checks in ``_Sink``
    cannot apply; instead everything it produced is validated post hoc and
    rule-breakers are deleted and reported, mirroring ``_Sink``'s refusals.
    ``-p`` pins an empty password so an encrypted archive fails fast instead
    of blocking on an interactive prompt.
    """
    sub.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["7z", "x", "-y", "-bd", "-p", f"-o{sub}", str(path.resolve())],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = tail[-1][:120] if tail else f"exit code {proc.returncode}"
        raise OSError(detail)
    skipped: list[str] = []
    for child in sorted(sub.rglob("*")):
        if child.is_symlink():
            child.unlink()
            skipped.append(f"{child.relative_to(sub).as_posix()}: symlink")
            continue
        if not child.is_file():
            continue
        rel = child.relative_to(sub).as_posix()
        if budget["files"] >= _UNPACK_MAX_FILES:
            child.unlink()
            skipped.append(f"{rel}: over file budget")
            continue
        size = child.stat().st_size
        if size > _UNPACK_MEMBER_MAX:
            child.unlink()
            skipped.append(f"{rel}: over member limit")
            continue
        if budget["bytes"] + size > _UNPACK_MAX_BYTES:
            child.unlink()
            skipped.append(f"{rel}: over byte budget")
            continue
        budget["files"] += 1
        budget["bytes"] += size
    return skipped


def _seven_zip() -> str | None:
    """Path to the system 7z binary, if this host has one.

    The image ships it (``p7zip-full``, which is 7-Zip proper on Debian
    trixie and reads RAR/RAR5).  Dev hosts often do not; the tail message in
    ``unpack_archive`` is what tells the model so.
    """
    return shutil.which("7z")


def _unique_dir(base: Path) -> Path:
    """Never mix this extraction into a previous run's output."""
    if not base.exists():
        return base
    index = 1
    while (base.parent / f"{base.name}-{index}").exists():
        index += 1
    return base.parent / f"{base.name}-{index}"


def _signature_offset(path: Path, kind: str) -> int:
    """Where a binary-only signature actually starts (0 when it is the header).

    Reporting the offset keeps the message honest for polyglots: a PNG with an
    embedded 7z is not "a 7z file", but "a 7z signature at 0x1234" is true and
    tells the model to carve from there.
    """
    pattern = b"\x37\x7a\xbc\xaf\x27\x1c" if kind == "7z" else b"Rar!\x1a\x07"
    try:
        with path.open("rb") as handle:
            head = handle.read(64 * 1024)
    except OSError:
        return 0
    found = head.find(pattern)
    return found if found >= 0 else 0


def unpack_archive(path: str = "", max_depth: int = 3, out_dir: str = "extracted") -> str:
    """Extract an archive safely, then keep going into nested archives.

    Nested archives are the norm in misc (``outer.zip`` holding ``inner.tar.gz``
    holding one PNG).  Doing that by hand costs one turn per layer and is where
    models lose the plot.

    Args:
        path: Archive file path.
        max_depth: Recurse into nested archives up to this depth, 1-5, default 3.
        out_dir: Destination directory; a numeric suffix is added if it exists.

    Returns:
        The extracted tree with per-file depth and size, plus everything that
        was refused (path escape, symlink, encrypted, over budget) and why.
    """
    source = resolve_path(path)
    if not source.is_file():
        return (
            f"[unpack_archive] not a file: {path!r}\n"
            "next: list the directory first (`ls -la`) -- attachments are often "
            "given a name different from the one in the statement."
        )
    depth_cap = _to_int(max_depth, 3, 1, 5)
    root = _unique_dir(resolve_path(out_dir or "extracted"))
    root.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    skipped: list[str] = []
    produced: list[Path] = []
    budget = {"bytes": 0, "files": 0}
    seven_zip = _seven_zip()

    def walk(item: Path, depth: int, kind: str | None = None) -> None:
        if kind is None:
            kind = _sniff(item)
        if not kind or depth > depth_cap:
            return
        sub = root if depth == 1 else root / f"_d{depth}"
        if kind in _BINARY_ONLY and seven_zip:
            # The system binary reads formats the stdlib cannot -- 7z, and on
            # current Debian also RAR/RAR5.  _from_7z validates its output
            # against the same gates as _Sink.
            try:
                skipped.extend(_from_7z(item, sub, budget))
            except (OSError, subprocess.SubprocessError) as exc:
                lines.append(f"! {item.name}: 7z failed ({type(exc).__name__})")
                return
        elif kind in _BINARY_ONLY:
            # No binary on this host.  Stop before the stdlib paths, which
            # would otherwise raise KeyError on the opener table -- the tail
            # message explains what to do instead.
            return
        else:
            sink = _Sink(sub, budget)
            try:
                if kind == "zip":
                    _from_zip(item, sink)
                elif kind == "tar":
                    _from_tar(item, sink)
                elif kind == "zstd":
                    _from_zstd(item, sink)
                else:
                    _from_stream(item, kind, sink)
            except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
                lines.append(f"! {item.name}: {kind} failed ({type(exc).__name__})")
                return
            skipped.extend(sink.skipped)
        for child in sorted(sub.rglob("*")):
            if not child.is_file():
                continue
            produced.append(child)
            lines.append(
                f"  d{depth} {child.relative_to(root).as_posix()}  "
                f"({child.stat().st_size} B)"
            )
            walk(child, depth + 1)

    kind = _sniff(source)
    walk(source, 1, kind)

    body = [
        f"[unpack_archive] {source.name} -> {root.as_posix()} "
        f"(detected {kind or 'unknown'}, depth {depth_cap})"
    ]
    body.extend(lines or ["  nothing extracted"])
    if skipped:
        body.append(f"refused {len(skipped)}:")
        body.extend(f"  - {entry}" for entry in skipped[:20])
    body.append(f"total {len(produced)} file(s), {budget['bytes']} B")
    if not produced:
        body.append(
            "next: nothing came out -- check what the file really is with "
            "file_triage/hexpeek; a wrong extension is common and the magic "
            "bytes are the authority."
        )
        if kind in _BINARY_ONLY and not seven_zip:
            where = _signature_offset(source, kind)
            at = "this IS that archive" if where == 0 else "the archive starts there"
            body.append(
                f"matched a {kind} signature at offset 0x{where:x} -- {at}, and this "
                f"image ships no {kind} reader. Do not retry unpack_archive; it will "
                "return the same line. Next: carve from that offset and read the "
                "container by hand (hexpeek + the struct module), or check whether "
                "the statement/strings already leaks the content. If it is encrypted, "
                "the password has to come from the challenge -- brute force here is a "
                "different, much more expensive problem."
            )
        elif kind in _BINARY_ONLY:
            body.append(
                f"next: the 7z binary ran on this {kind} and produced nothing "
                "usable -- the archive is empty, corrupt, truncated, or "
                "password-protected. Do not retry unpack_archive; it will fail "
                "the same way. If it is encrypted, the password has to come "
                "from the challenge."
            )
    else:
        body.append(
            "next: run file_triage on the largest extracted file; for text "
            "files grep is cheaper than opening each one."
        )
    return _clip("\n".join(body))

# ---------------------------------------------------------------------------
# 3. hexpeek -- xxd for a container that has no xxd
# ---------------------------------------------------------------------------


def hexpeek(path: str = "", offset: int = 0, length: int = 256) -> str:
    """Show bytes as hex + ASCII, so a header can be read without xxd.

    Args:
        path: File path.
        offset: Start byte, accepts 0x-prefixed values.
        length: Bytes to show, 1-1024, default 256.

    Returns:
        One line per 16 bytes with the file offset, plus a note when more data
        follows (and at which offset).
    """
    target = resolve_path(path)
    if not target.is_file():
        return (
            f"[hexpeek] not a file: {path!r}\n"
            "next: `ls -la` in the working directory to get the real name."
        )
    size = target.stat().st_size
    start = _to_int(offset, 0, 0, 1 << 40)
    span = _to_int(length, 256, 1, _HEX_MAX)
    if start > size:
        return f"[hexpeek] offset {start} is past the end (file is {size} B)."
    with target.open("rb") as handle:
        handle.seek(start)
        data = handle.read(span)

    rows = [f"[hexpeek] {target.name}  {size} B  range [{start}, {start + len(data)})"]
    for index in range(0, len(data), _HEX_WIDTH):
        chunk = data[index : index + _HEX_WIDTH]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk).ljust(_HEX_WIDTH * 3 - 1)
        text_part = "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in chunk)
        rows.append(f"{start + index:08x}  {hex_part}  |{text_part}|")
    if start + len(data) < size:
        rows.append(
            f"... {size - start - len(data)} B not shown -- continue with "
            f"offset={start + len(data)}"
        )
    return _clip("\n".join(rows))


# ---------------------------------------------------------------------------
# 4/5. tcp -- one round trip, and a batch that shares one connection
# ---------------------------------------------------------------------------


def _connect(host: str, port: int, timeout: float, tls: bool, sni: str) -> socket.socket:
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except socket.gaierror as exc:
        hint = ""
        if host.lower().endswith(".internal"):
            hint = (
                " The host is *.internal: either the challenge VPN is not up, or "
                "you reused a stale node name. Use the URL the platform returned."
            )
        raise _NonWebError(f"[tcp] DNS failed for {host}: {exc}.{hint}") from None
    except ConnectionRefusedError:
        # The host answered with RST: the box is up, the port is not open.  This
        # is *not* evidence of a dead target, and saying "cannot connect" here
        # would be the same lie in a different shape.
        raise _NonWebError(
            f"[tcp] connection refused by {host}:{port}. "
            "next: confirm the port from the task statement; a refused port on a "
            "running box usually means the wrong port, not a dead box."
        ) from None
    except (TimeoutError, socket.timeout):
        # A SYN that nobody answers: a firewall dropping it looks exactly like a
        # dead box.  Report the fact (we waited, nothing came back) and let the
        # caller decide whether that means "wrong port" or "nothing there".
        raise _NonWebError(
            f"[tcp] connect timed out to {host}:{port} after {timeout:g}s. "
            "next: retry once; a host that keeps timing out on this exact port "
            "is not answering."
        ) from None
    except OSError as exc:
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            raise _NonWebError(
                f"[tcp] cannot reach {host}:{port} ({type(exc).__name__}: {exc}). "
                "next: no route to that address -- check the VPN/tunnel before "
                "assuming the service is down."
            ) from None
        raise _NonWebError(
            f"[tcp] cannot connect to {host}:{port} ({type(exc).__name__}: {exc}). "
            "next: confirm the port from the task statement."
        ) from None
    if not tls:
        return raw
    try:
        import ssl

        context = ssl.create_default_context()
        # CTF services routinely use self-signed certificates; the goal is the
        # protocol, not the PKI.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context.wrap_socket(raw, server_hostname=(sni or host))
    except Exception as exc:  # noqa: BLE001
        try:
            raw.close()
        except OSError:
            pass
        raise _NonWebError(
            f"[tcp] TLS handshake failed ({type(exc).__name__}: {exc}). "
            "next: this platform serves every TCP service behind TLS-SNI, so "
            "a wrong SNI is the usual cause -- retry with sni='<vhost>' "
            "first. Drop to tls=false only when the task statement itself "
            "says the service is plaintext: an empty plain reply is this "
            "platform's signature that the port wants TLS, so tls=false "
            "right after a failed handshake usually loops straight back to "
            "that empty state. Plain TCP does exist in CTF, but it is not "
            "the default here."
        ) from None


#: First-line markers that classify a ``tcp`` / ``tcp_batch`` result.  These
#: live here, next to the code that *emits* the strings, so the vocabulary has
#: exactly one owner: ``target_absent`` consumes :func:`tcp_connect_state`
#: instead of re-deriving the wording, which is how two copies drift apart.
#:
#: Two of these are failures and still mean **live**.  A TLS handshake failure
#: and a send failure both happen *after* the TCP connect succeeded -- the peer
#: is up and listening, it just did not like what came next.  Counting those as
#: "unreachable" would kill a target that is answering.
_TCP_LIVE_MARKERS: Final = (
    " connected in ",  # tcp(): TCP handshake completed
    " payload(s) same_conn=",  # tcp_batch(): connected, ran the batch
    "[tcp] TLS handshake failed",  # accepted TCP, then the handshake broke
    "[tcp] send failed",  # accepted TCP, then closed on us
)
_TCP_DNS_PREFIX: Final = "[tcp] DNS failed for "
_TCP_REFUSED_PREFIX: Final = "[tcp] connection refused by "
_TCP_TIMEOUT_PREFIX: Final = "[tcp] connect timed out to "
_TCP_UNREACHABLE_PREFIX: Final = "[tcp] cannot reach "
_TCP_LINE_PREFIXES: Final = ("[tcp] ", "[tcp_batch] ")


def tcp_connect_state(text: str) -> str | None:
    """Classify a ``tcp`` / ``tcp_batch`` result by what the *connection* did.

    Only the first line is read: that is where both tools state the connection
    outcome, and later lines are response bytes that can contain anything.

    Returns:

    ``"live"``
        The peer accepted the TCP connection -- a handshake completed, or it
        accepted us and then dropped us (TLS handshake failure, send failure).
        Every one of these proves the host is up with something listening.
    ``"dns"``
        The host name did not resolve.  Host-level, not port-level.
    ``"refused"``
        The host answered with RST: the box is up, that port is closed.
    ``"timeout"``
        The SYN went unanswered -- a firewall dropping it looks identical to a
        dead box, so this is weak evidence and the caller should weigh it.
    ``"unreachable"``
        No route to the address at all (ENETUNREACH / EHOSTUNREACH).
    ``None``
        Not a connectivity verdict: argument errors, empty payload lists, or
        text this module did not produce.  Callers must not count ``None``.
    """
    if not text:
        return None
    lines = text.strip().splitlines()
    if not lines:
        return None
    head = lines[0]
    if not head.startswith(_TCP_LINE_PREFIXES):
        return None
    for marker in _TCP_LIVE_MARKERS:
        if marker in head:
            return "live"
    if head.startswith(_TCP_DNS_PREFIX):
        return "dns"
    if head.startswith(_TCP_REFUSED_PREFIX):
        return "refused"
    if head.startswith(_TCP_TIMEOUT_PREFIX):
        return "timeout"
    if head.startswith(_TCP_UNREACHABLE_PREFIX):
        return "unreachable"
    return None


def _drain(
    sock: socket.socket, expect: bytes | None, read_timeout: float, cap: int
) -> tuple[bytes, bool]:
    """Read until ``expect`` appears, the peer closes, or the window expires.

    Returns ``(buffer, closed)``.  ``closed`` is True **only** when ``recv``
    returned ``b""`` -- a real FIN from the peer.  A timeout, an ``OSError`` and
    hitting ``cap`` all leave the connection up, so they must not be reported as
    a close: a caller that conflates them cannot tell "the peer said what it had
    and hung up" from "we stopped reading too early", and says the wrong thing
    to the model about the reply it just got.
    """
    buffer = b""
    closed = False
    sock.settimeout(read_timeout)
    deadline = time.monotonic() + read_timeout
    while len(buffer) < cap:
        try:
            chunk = sock.recv(min(4096, cap - len(buffer)))
        except (TimeoutError, socket.timeout):
            break
        except OSError:
            break
        if not chunk:
            closed = True
            break
        buffer += chunk
        if expect and expect in buffer:
            break
        if time.monotonic() > deadline:
            break
    return buffer, closed


def _window(data: bytes, start: int, stop: int) -> str:
    """Printable form of ``data[start:stop]`` (newlines kept visible)."""
    return "".join(
        chr(byte) if 32 <= byte < 127
        else ("\\n" if byte == 10 else ("\\r" if byte == 13 else "."))
        for byte in data[start:stop]
    )


def _pending(sock: socket.socket, closed: bool = False) -> bool:
    """True when the socket still has bytes buffered beyond what we read.

    ``_drain`` stops the moment it has ``cap`` bytes, so ``len(body) == cap``
    only means "maybe more" -- the peer may have sent exactly ``cap`` and shut
    down.  On ``same_conn`` unread bytes are consumed as the START of the next
    payload's response, which silently shifts every following row.

    ``select`` cannot answer this: a socket sitting at EOF is **readable**, so
    a zero-timeout select after a complete one-shot reply says "more coming"
    when the peer has already hung up.  Peek one byte instead -- ``b""`` is EOF,
    a byte is unread data.  ``select`` stays as the fallback for sockets that
    refuse ``MSG_PEEK`` (``SSLSocket`` raises ``ValueError`` on non-zero flags).
    ``closed`` short-circuits the common case where the drain already saw FIN.
    """
    if closed:
        return False
    try:
        previous = sock.gettimeout()
    except (OSError, ValueError):
        return False
    try:
        sock.settimeout(0.0)
        return bool(sock.recv(1, socket.MSG_PEEK))
    except (TimeoutError, BlockingIOError, socket.timeout):
        return False
    except (OSError, ValueError):
        try:
            return bool(select.select([sock], [], [], 0)[0])
        except (OSError, ValueError):
            return False
    finally:
        try:
            sock.settimeout(previous)
        except (OSError, ValueError):
            pass


def _render(data: bytes, label: str, dump_path: str = "") -> str:
    """Render a body as head *and* tail windows, and say what is not shown.

    The old version printed the total length and then only the first 256 hex /
    600 ASCII bytes, with no marker at the cut: ``reply 1100 B`` followed by a
    window that stops mid-line is indistinguishable from a reply that ended
    there.  On a byte-at-a-time oracle the byte that decides the answer is
    usually the last one, so the tail window is the one that matters.
    """
    total = len(data)
    if not total:
        return f"{label}: (empty)"
    lines = [f"{label} {total} B"]
    hex_head_end = min(total, _RENDER_HEX_HEAD)
    ascii_head_end = min(total, _RENDER_ASCII_HEAD)
    lines.append(f"  hex[0:{hex_head_end}] {data[:hex_head_end].hex()}")
    lines.append(f"  ascii[0:{ascii_head_end}] {_window(data, 0, ascii_head_end)}")
    if total <= ascii_head_end and total <= hex_head_end:
        return "\n".join(lines)
    ascii_tail_start = max(ascii_head_end, total - _RENDER_ASCII_TAIL)
    if ascii_tail_start > ascii_head_end:
        lines.append(
            f"  ascii[{ascii_tail_start}:{total}] {_window(data, ascii_tail_start, total)}"
        )
        lines.append(
            f"  omitted {ascii_tail_start - ascii_head_end} B at offset "
            f"{ascii_head_end}..{ascii_tail_start} -- the middle is NOT shown"
        )
    if total > hex_head_end:
        hex_tail_start = max(hex_head_end, total - _RENDER_HEX_TAIL)
        lines.append(f"  hex[{hex_tail_start}:{total}] {data[hex_tail_start:total].hex()}")
    if dump_path:
        lines.append(
            f'  full body: {dump_path} -- hexpeek(path, offset=<n>, length=<m>) '
            "reads any window; do not reconnect to re-read bytes already received"
        )
    else:
        lines.append(
            "  full body NOT stored (no writable dump dir); only the windows above "
            "are readable -- the cut is a display limit, not the end of the reply"
        )
    return "\n".join(lines)


def _render_body(data: bytes, label: str, tag: str) -> str:
    """``_render`` with a dump, only when the visible windows cannot hold it all."""
    dump = ""
    if len(data) > _RENDER_ASCII_HEAD or len(data) > _RENDER_HEX_HEAD:
        dump = _dump(data, tag)
    return _render(data, label, dump)


def _batch_row(index: int, sent: int, body: bytes, offset: int, cap: int) -> str:
    """One comparison line: both edges of the body plus where it lives."""
    total = len(body)
    if total <= _ROW_FULL:
        windows = [f"hex={body.hex()}", f"ascii={_window(body, 0, total)!r}"]
    else:
        if total <= 4 * _ROW_EDGE:
            head_end = tail_start = total // 2
        else:
            head_end, tail_start = _ROW_EDGE, total - _ROW_EDGE
        windows = [
            f"hex[0:{head_end}]={body[:head_end].hex()}",
            f"hex[{tail_start}:{total}]={body[tail_start:total].hex()}",
            f"ascii[0:{head_end}]={_window(body, 0, head_end)!r}",
            f"ascii[{tail_start}:{total}]={_window(body, tail_start, total)!r}",
        ]
        if tail_start > head_end:
            windows.append(f"+{tail_start - head_end} B omitted")
    flag = f" HIT-CAP({cap})" if total >= cap else ""
    return f"#{index} sent {sent} B -> recv {total} B{flag} @{offset} " + " ".join(windows)


def _tcp_round(
    host: str,
    target_port: int,
    raw: bytes,
    expect_bytes: bytes | None,
    window: float,
    cap: int,
    tls: bool,
    sni: str,
    connect_timeout: float | None = None,
) -> tuple[str, object]:
    """One connect -> optional banner -> optional send -> read cycle.

    Returns ``("ok", (banner, body, capped, pending, closed))``,
    ``("send_failed", "<exception text>")`` or ``("error", "<formatted [tcp] line>")``.
    Kept apart from :func:`tcp` so the plain attempt and the TLS retry share one
    read loop -- two copies is how ``expect`` handling drifted before.

    ``connect_timeout`` replaces the default ``min(10, window + 7)`` budget.
    That default exists for *dialling*; the TLS probe also spends it on the
    handshake read, where a silent plaintext port keeps us waiting the whole
    time, so the caller caps it explicitly.
    """
    connect_budget = (
        min(10.0, window + 7.0) if connect_timeout is None else connect_timeout
    )
    try:
        sock = _connect(host, target_port, connect_budget, bool(tls), sni)
    except _NonWebError as exc:
        return "error", str(exc)
    try:
        # Grab the banner first: many services print a prompt and then wait, so
        # sending immediately would bury the prompt in our echo.
        banner = b""
        try:
            sock.settimeout(0.4)
            banner = sock.recv(4096)
        except (TimeoutError, socket.timeout, OSError):
            banner = b""
        if raw:
            try:
                sock.sendall(raw)
            except OSError as exc:
                return "send_failed", str(exc)
        body, closed = _drain(sock, expect_bytes, window, cap)
        pending = _pending(sock, closed)
        return "ok", (banner, body, len(body) >= cap, pending, closed)
    finally:
        try:
            sock.close()
        except OSError:
            pass


#: TLS record types visible to a *plain* round when the port really speaks TLS:
#: 0x15 = alert (the listener rejected our non-handshake bytes), 0x16 = handshake.
_TLS_RECORD_HEADS: Final = (b"\x15", b"\x16")


def _plain_looks_like_tls(banner: bytes, body: bytes) -> bool:
    """Decide whether a plain round is worth repeating behind TLS.

    Two signals: nothing came back at all (a TLS listener stays silent until it
    sees a ClientHello), or the first byte is a TLS record type. A banner or any
    other content means the plain service works, so normal targets never pay for
    the extra connection.
    """
    if banner:
        return False
    if not body:
        return True
    return body[:1] in _TLS_RECORD_HEADS


#: Wall-clock ceiling for the auto-TLS probe, in seconds.  The probe exists to
#: catch "the port is TLS and stayed silent on plaintext"; a handshake that has
#: not completed in this long is not going to.  Without a ceiling the probe
#: inherits the 10 s connect budget, which a plaintext service that is simply
#: waiting for input spends in full -- one ``tcp`` call then costs ~13 s.
_TLS_PROBE_TIMEOUT: Final = 4.0


def _tls_retry(
    host: str,
    target_port: int,
    window: float,
    cap: int,
    sni: str,
) -> tuple[bytes, bytes, bool, bool, bool] | None:
    """Probe the port behind TLS; keep the result only if it produced bytes.

    The probe sends **no** payload.  Replaying the caller's bytes on a fresh
    connection silently feeds a one-shot or counting service twice; the plain
    attempt already delivered them.  So the probe only reads a banner, and an
    empty probe is discarded -- the caller keeps its own output plus a hint
    rather than silently swapping in another connection's silence.
    """
    status, payload = _tcp_round(
        host,
        target_port,
        b"",
        None,
        window,
        cap,
        True,
        sni or host,
        min(_TLS_PROBE_TIMEOUT, max(2.0, window + 1.0)),
    )
    if status != "ok":
        return None
    banner, body, _capped, _pending_now, _closed = payload  # type: ignore[misc]
    if not banner and not body:
        return None
    return payload  # type: ignore[return-value]


def tcp(
    host: str = "",
    port: int = 0,
    payload: str = "",
    hex_mode: bool = False,
    expect: str = "",
    read_timeout: float = 3.0,
    max_recv: int = 4096,
    tls: bool = False,
    sni: str = "",
) -> str:
    """Connect once, optionally send a payload, and show the banner plus reply.

    This exists because ``nc`` and ``pwntools`` are not guaranteed in the image,
    and because a raw socket gives both the bytes and the banner in one call --
    the "interactive tool" gap EnIGMA identifies as the main blocker on
    remote-service challenges.

    Args:
        host: Target host.
        port: Target port.
        payload: Bytes to send. Text by default; hex when ``hex_mode`` is set.
        hex_mode: Interpret ``payload`` as hex (for binary protocols and
            exploit bytes).
        expect: Stop reading early once this substring arrives.
        read_timeout: Per-read window in seconds, default 3.
        max_recv: Cap on bytes read back, default 4096.
        tls: Wrap in TLS (accepts self-signed certificates).
        sni: SNI name when the vhost differs from ``host``.

    Returns:
        Connect timing, banner, reply (hex + ASCII) and whether ``expect`` hit.
    """
    if not host:
        return "[tcp] host is empty. Format: tcp(host='node1.ctfy.run', port=1337)"
    target_port = _to_int(port, 0, 0, 65535)
    if target_port <= 0:
        return f"[tcp] invalid port {port!r}. It must be 1-65535."
    if hex_mode:
        try:
            raw = bytes.fromhex(str(payload or "").strip())
        except ValueError as exc:
            return f"[tcp] hex_mode payload is not valid hex: {exc}"
    else:
        raw = str(payload or "").encode("utf-8", "surrogateescape")

    window = min(max(float(read_timeout or 3.0), 0.2), 30.0)
    cap = _to_int(max_recv, 4096, 16, 65536)
    started = time.time()
    expect_bytes = expect.encode("utf-8", "surrogateescape") if expect else None
    status, outcome = _tcp_round(
        host, target_port, raw, expect_bytes, window, cap, bool(tls), sni
    )
    if status == "error":
        return outcome  # already a formatted ``[tcp] ...`` line
    if status == "send_failed":
        return f"[tcp] send failed: {outcome}. The peer closed after the banner."
    banner, body, capped, pending, closed = outcome
    auto_tls = False
    tls_empty = False
    if not tls and _plain_looks_like_tls(banner, body):
        retried = _tls_retry(host, target_port, window, cap, sni)
        if retried is not None:
            banner, body, capped, pending, closed = retried
            auto_tls = True
        else:
            tls_empty = True

    elapsed_ms = (time.time() - started) * 1000
    parts = [
        f"[tcp] {host}:{target_port} connected in {elapsed_ms:.0f} ms "
        f"(sent {len(raw)} B, tls={bool(tls) or auto_tls})"
    ]
    if auto_tls:
        parts.append(
            "auto-TLS: the plain round carried no protocol bytes, so this reply came "
            f"from a second connection with tls=True, sni={sni or host}. Pass tls=True "
            "explicitly on the next call -- this platform serves every TCP service "
            "behind TLS-SNI. Note: your payload was NOT resent on that second "
            "connection, so any state it created lives on the plain connection only; "
            "if the service needs input, repeat the call with tls=True."
        )
    expect_hit = bool(expect_bytes) and expect_bytes in body
    if banner:
        parts.append(_render_body(banner, "banner", "banner"))
    if body:
        parts.append(_render_body(body, "reply", "reply"))
    elif not banner:
        if tls_empty and closed:
            parts.append(
                "no bytes received -- the peer accepted the connection and closed it "
                "without a word, and the TLS probe with tls=True came back empty too: "
                "this port is speaking neither protocol. Re-check the port (and the "
                "host) before retrying."
            )
        elif tls_empty:
            parts.append(
                "no bytes received -- the service may be waiting for input first "
                "(send a newline), and a TLS retry with tls=True also came back "
                "empty, so if a banner was expected the SNI may be wrong: "
                "pass sni='<vhost>'."
            )
        elif closed:
            parts.append(
                "no bytes received -- the peer accepted the connection and closed it "
                "without sending anything. Nothing was waiting to talk: re-check the "
                "port, or send a payload first if the service speaks only when spoken to."
            )
        else:
            parts.append("no bytes received -- the service is waiting for input first.")
    if capped:
        parts.append(
            f"cap: the read stopped at max_recv={cap} B, so the peer may still have "
            "bytes to send -- what is shown is a prefix, NOT the whole reply. "
            f"Rerun with max_recv={min(cap * 4, 65536)} (or read the dump by offset) "
            "before concluding anything from these bytes."
        )
    elif pending and not expect_hit:
        parts.append(
            "note: the peer was still sending when the read window closed "
            f"(read_timeout={window:g}s), so this reply is a prefix. Rerun with a "
            "larger read_timeout."
        )
    if expect:
        if expect_hit:
            parts.append("expect: MATCHED")
        elif capped or pending:
            parts.append(
                f"expect: NOT FOUND in the {len(body)} B that were read -- the read "
                "hit its limit, so absence here is not evidence of absence."
            )
        else:
            parts.append("expect: not found")
    if not body and raw:
        parts.append(
            "next: nothing came back after the payload. For a line-based service "
            "the terminator is usually a newline; retry with payload='...\\n'."
        )
    return _clip("\n".join(parts))


def tcp_batch(
    host: str = "",
    port: int = 0,
    payloads: list[str] | None = None,
    hex_mode: bool = True,
    read_timeout: float = 2.0,
    max_recv: int = 1024,
    same_conn: bool = True,
    tls: bool = False,
    sni: str = "",
) -> str:
    """Send several payloads and report one compact line per response.

    The point is *comparison*: padding oracles and byte-by-byte leaks are
    decided by which response differs, and doing that in one call keeps the
    difference in one context window instead of 200 separate ones.

    Args:
        host: Target host.
        port: Target port.
        payloads: Candidate payloads, max 200.
        hex_mode: Payloads are hex (default true; false for text lines).
        read_timeout: Per-payload read window, default 2 seconds.
        max_recv: Cap per response, default 1024 bytes.
        same_conn: Reuse one connection (needed for per-connection state); set
            false only when the service rejects pipelining.
        tls: Wrap in TLS.
        sni: SNI name override.

    Returns:
        Header, a legend line, then one ``#i sent N B -> recv M B ... @offset``
        line per payload -- both the head AND the tail of each response, plus
        the batch offset where the full bytes live -- so a response that differs
        only in its last byte is still visible without reading 200 bodies.
    """
    items = [item for item in (payloads or []) if isinstance(item, str)]
    if not items:
        return "[tcp_batch] payloads is empty. Pass a list of candidates."
    if len(items) > _BATCH_MAX:
        items = items[:_BATCH_MAX]
    target_port = _to_int(port, 0, 0, 65535)
    if not host or target_port <= 0:
        return f"[tcp_batch] need host and a port in 1-65535 (got {host!r}:{port!r})."

    window = min(max(float(read_timeout or 2.0), 0.2), 30.0)
    cap = _to_int(max_recv, 1024, 16, 65536)
    rows: list[str] = []
    chunks: list[bytes] = []
    cursor = 0
    cap_warned = False
    shifted = False
    started = time.time()
    try:
        sock = _connect(host, target_port, min(10.0, window + 7.0), bool(tls), sni)
        try:
            sock.settimeout(0.3)
            try:
                sock.recv(4096)
            except (TimeoutError, socket.timeout, OSError):
                pass
            for index, item in enumerate(items):
                if time.time() - started > 120:
                    rows.append(f"# stopped after {index}/{len(items)}: 120s wall")
                    break
                try:
                    raw = (
                        bytes.fromhex(item.strip())
                        if hex_mode
                        else item.encode("utf-8", "surrogateescape")
                    )
                except ValueError:
                    rows.append(f"#{index} skipped: not valid hex")
                    continue
                try:
                    sock.sendall(raw)
                except OSError as exc:
                    rows.append(f"#{index} send failed: {exc}")
                    break
                body, closed = _drain(sock, None, window, cap)
                hit_cap = len(body) >= cap
                leftover = _pending(sock, closed) if hit_cap else False
                rows.append(_batch_row(index, len(raw), body, cursor, cap))
                chunks.append(body)
                cursor += len(body)
                if hit_cap and not cap_warned:
                    cap_warned = True
                    rows.append(
                        f"  ^ recv stopped at max_recv={cap} B: this row (and any like "
                        "it) is a PREFIX, not the whole response. Rerun with "
                        f"max_recv={min(cap * 4, 65536)} if the tail matters."
                    )
                if leftover and same_conn:
                    shifted = True
                if not same_conn:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    sock = _connect(host, target_port, min(10.0, window + 7.0), bool(tls), sni)
                    sock.settimeout(0.3)
                    try:
                        sock.recv(4096)
                    except (TimeoutError, socket.timeout, OSError):
                        pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except _NonWebError as exc:
        return str(exc)

    head = (
        f"[tcp_batch] {host}:{target_port} {len(items)} payload(s) "
        f"same_conn={same_conn} in {time.time() - started:.1f}s"
    )
    long_bodies = [body for body in chunks if len(body) > _ROW_FULL]
    dump = _dump(b"".join(chunks), "batch") if long_bodies else ""
    if dump:
        where = (
            f"  every response is stored back-to-back in {dump}; '@N' above is that "
            f"file's byte offset. hexpeek(path, offset=N, length=M) reads any window, "
            "read_file(path) reads the text -- re-read from the dump, do not resend"
        )
    else:
        where = (
            "  '@N' is the byte offset within this batch's responses. Nothing was "
            "written to disk, so re-reading a body means resending its payload"
        )
    if shifted:
        rows.append(
            "  ! residual bytes from a response that hit max_recv were read as the "
            "START of the next response: rows after that point are SHIFTED. Rerun "
            "with a larger max_recv, or same_conn=false, before trusting them."
        )
    if not any(chunks):
        rows.append(
            "  ! every payload came back empty. If the port is TLS-only, a plain "
            "connection returns nothing at all: rerun with tls=True (sni defaults "
            "to the host) before concluding the service ignores these payloads."
        )
    tail = (
        "next: the deciding bytes are usually at the TAIL (padding, MAC, status "
        "byte, trailing newline), not the first 48 -- compare BOTH edges above. "
        "An equal 'recv' length does not mean an equal response. Only if both "
        "edges match everywhere is the hypothesis actually dead."
    )
    lines = [head, where] + rows + [tail]
    out = "\n".join(lines)
    clipped = _clip(out)
    if len(clipped) < len(out):
        text_dump = _dump(out, "batch-text")
        if text_dump:
            clipped += f"\n...[rows cut by the display limit; full text: {text_dump}" \
                       " -- read_file(path) shows every row]"
        else:
            clipped += (
                "\n...[rows cut by the display limit and the report text could not "
                "be stored; split the payload list and rerun]"
            )
    return clipped

# ---------------------------------------------------------------------------
# 6. elfpeek -- enough ELF to decide the next move
# ---------------------------------------------------------------------------


# ``RELRO`` on its own answers "is there a RELRO segment", which is not the
# question a pwn plan asks.  The three levels below are checksec's wording on
# purpose: writeups say ``Partial RELRO`` / ``GOT writable`` and the model has
# to be able to match what it reads here against the technique it remembers.
_RELRO_NOTE = {
    "No RELRO": "GOT writable",
    "Partial RELRO": ".got.plt writable, .got read-only",
    "Full RELRO": "GOT read-only after relocation -- no GOT overwrite",
}


class _Elf:
    """Minimal ELF reader: header, sections, symbols, program headers.

    Only the fields a CTF needs.  Deliberately not a general-purpose parser:
    every extra field is code to maintain and bytes of context the model reads.
    """

    def __init__(self, data: bytes) -> None:
        if len(data) < 52 or data[:4] != b"\x7fELF":
            raise _NonWebError("[elfpeek] not an ELF file (bad magic). Use file_triage first.")
        self.data = data
        self.is64 = data[4] == 2
        self.endian = "<" if data[5] == 1 else ">"
        self.e_type = struct.unpack_from(self.endian + "H", data, 16)[0]
        self.e_machine = struct.unpack_from(self.endian + "H", data, 18)[0]
        if self.is64:
            self.e_entry, self.e_phoff, self.e_shoff = struct.unpack_from(
                self.endian + "QQQ", data, 24
            )
            (self.e_phentsize, self.e_phnum, self.e_shentsize,
             self.e_shnum, self.e_shstrndx) = struct.unpack_from(self.endian + "HHHHH", data, 54)
        else:
            self.e_entry, self.e_phoff, self.e_shoff = struct.unpack_from(
                self.endian + "III", data, 24
            )
            (self.e_phentsize, self.e_phnum, self.e_shentsize,
             self.e_shnum, self.e_shstrndx) = struct.unpack_from(self.endian + "HHHHH", data, 42)

    def program_headers(self) -> list[tuple[int, int, int, int, int]]:
        rows: list[tuple[int, int, int, int, int]] = []
        for index in range(min(self.e_phnum, 512)):
            offset = self.e_phoff + index * self.e_phentsize
            if offset + self.e_phentsize > len(self.data):
                break
            if self.is64:
                p_type, p_flags = struct.unpack_from(self.endian + "II", self.data, offset)
                p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from(
                    self.endian + "QQQQ", self.data, offset + 8
                )
            else:
                (p_type, p_offset, p_vaddr, _paddr,
                 p_filesz, _memsz, p_flags, _align) = struct.unpack_from(
                    self.endian + "IIIIIIII", self.data, offset
                )
            rows.append((p_type, p_flags, p_offset, p_vaddr, p_filesz))
        return rows

    def dynamic_tags(self) -> dict[int, int]:
        """``d_tag -> d_val`` from ``PT_DYNAMIC``, stopping at the first ``DT_NULL``.

        Reached through the program headers, so it works on a stripped binary with
        no section headers at all.  Needed because Full RELRO is not a segment
        flag: it is ``PT_GNU_RELRO`` *plus* a request for eager binding, and that
        request is spelled three different ways depending on the linker.
        """
        tags: dict[int, int] = {}
        size = 16 if self.is64 else 8
        fmt = self.endian + ("qQ" if self.is64 else "iI")
        for p_type, _flags, p_offset, p_vaddr, p_filesz in self.program_headers():
            if p_type != 2:  # PT_DYNAMIC
                continue
            stop = min(p_offset + p_filesz, len(self.data))
            for position in range(p_offset, stop - size + 1, size):
                tag, value = struct.unpack_from(fmt, self.data, position)
                if tag == 0:  # DT_NULL terminates the array
                    return tags
                tags[tag] = value
        return tags

    def _section_rows(self) -> list[tuple[int, int, int, int, int, int]]:
        rows = []
        for index in range(min(self.e_shnum, 1024)):
            offset = self.e_shoff + index * self.e_shentsize
            if offset + self.e_shentsize > len(self.data):
                break
            if self.is64:
                name, sh_type, flags, addr, sh_offset, size = struct.unpack_from(
                    self.endian + "IIQQQQ", self.data, offset
                )
            else:
                name, sh_type, flags, addr, sh_offset, size = struct.unpack_from(
                    self.endian + "IIIIII", self.data, offset
                )
            rows.append((name, sh_type, flags, addr, sh_offset, size))
        return rows

    def _section_rows_linked(self) -> list[tuple[int, int, int, int, int, int, int]]:
        """Section rows including ``sh_link``: the index of the string table.

        ``sh_name`` is an *offset into the section-name string table*, not a
        section index.  Reading it as an index is why every symbol lookup used
        to come back empty on a normal linked binary: ``sh_name`` is usually in
        the hundreds, so ``sh_name >= len(rows)`` skipped every symbol table.
        """
        rows = []
        for index in range(min(self.e_shnum, 1024)):
            offset = self.e_shoff + index * self.e_shentsize
            if offset + self.e_shentsize > len(self.data):
                break
            if self.is64:
                (name, sh_type, flags, addr, sh_offset, size,
                 link) = struct.unpack_from(
                    self.endian + "IIQQQQI", self.data, offset
                )
            else:
                (name, sh_type, flags, addr, sh_offset, size,
                 link) = struct.unpack_from(
                    self.endian + "IIIIIII", self.data, offset
                )
            rows.append((name, sh_type, flags, addr, sh_offset, size, link))
        return rows

    def sections(self) -> list[tuple[str, int, int, int]]:
        rows = self._section_rows()
        if not rows:
            return []
        string_offset = 0
        if self.e_shstrndx < len(rows):
            string_offset = rows[self.e_shstrndx][4]
        out = []
        for name, _typ, _flags, addr, offset, sec_size in rows:
            label = ""
            if string_offset and string_offset + name < len(self.data):
                end = self.data.find(b"\0", string_offset + name)
                stop = end if end > 0 else string_offset + name + 64
                label = self.data[string_offset + name : stop].decode("latin-1", "replace")
            out.append((label, addr, offset, sec_size))
        return out

    def symbols(self) -> list[tuple[str, int, int]]:
        """Return ``(name, value, type)`` for every .symtab/.dynsym entry.

        Two header fields are easy to swap, and both were wrong here:

        * the string table is the symbol section's ``sh_link``; ``sh_name`` is
          only that section's own name offset;
        * ``st_info`` packs *type* in the low nibble and *binding* in the high
          one, so ``info >> 4`` reports GLOBAL as a type and turns every FUNC
          into OBJECT.

        Neither bug was visible with the old fixture: it had no section header
        table at all, so this path never ran.
        """
        rows = self._section_rows_linked()
        out: list[tuple[str, int, int]] = []
        for _name, sh_type, _flags, _addr, offset, size, link in rows:
            if sh_type not in (2, 11):  # SHT_SYMTAB / SHT_DYNSYM
                continue
            if not 0 <= link < len(rows):
                continue
            string_offset = rows[link][4]
            entry_size = 24 if self.is64 else 16
            for position in range(offset, min(offset + size, len(self.data)), entry_size):
                if position + entry_size > len(self.data):
                    break
                if self.is64:
                    str_name, info, _other, _shndx, value, _sz = struct.unpack_from(
                        self.endian + "IBBHQQ", self.data, position
                    )
                else:
                    str_name, value, _sz, info, _other, _shndx = struct.unpack_from(
                        self.endian + "IIIBBH", self.data, position
                    )
                if not str_name:
                    continue
                base = string_offset + str_name
                if base >= len(self.data):
                    continue
                end_byte = self.data.find(b"\0", base)
                stop = end_byte if end_byte > 0 else base + 64
                label = self.data[base:stop].decode("latin-1", "replace")
                out.append((label, value, info & 0xF))
        return out

    def strings(self, min_len: int = 4, limit: int = 80, utf16: bool = False) -> list[str]:
        if utf16:
            pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % max(2, min_len))
            wide = [match.decode("utf-16-le", "replace") for match in pattern.findall(self.data)]
            pattern_be = re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % max(2, min_len))
            wide += [match.decode("utf-16-be", "replace") for match in pattern_be.findall(self.data)]
            return wide[:limit]
        found: list[str] = []
        current = b""
        for byte in self.data:
            if 32 <= byte < 127:
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    found.append(current.decode("latin-1"))
                current = b""
                if len(found) >= limit * 20:
                    break
        if len(current) >= min_len:
            found.append(current.decode("latin-1"))
        keys = ("flag", "FLAG", "pass", "admin", "secret", "key", "token", "/bin/sh", "debug")
        # Keyword hit first, then length: a 200-char help string is rarely the
        # answer, and the list is capped at ``limit``.
        found.sort(key=lambda text: (not any(key in text for key in keys), -len(text)))
        return found[:limit]

    def security(self) -> dict[str, object]:
        info: dict[str, object] = {
            "PIE": self.e_type == 3,
            "type": {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN"}.get(self.e_type, str(self.e_type)),
            "NX": None,
            "canary": False,
            "RELRO": False,
            "RELRO_level": "No RELRO",
            "BIND_NOW": False,
        }
        relro_segment = False
        for p_type, p_flags, _offset, _vaddr, _filesz in self.program_headers():
            if p_type == 0x6474E551:  # PT_GNU_STACK
                info["NX"] = not (p_flags & 1)
            if p_type == 0x6474E552:  # PT_GNU_RELRO
                relro_segment = True
        # glibc binds eagerly if the linker asked for it in any of three spellings;
        # checking only one of them reports Partial RELRO for a Full RELRO binary.
        tags = self.dynamic_tags()
        bind_now = (
            24 in tags  # DT_BIND_NOW
            or bool(tags.get(30, 0) & 0x8)  # DT_FLAGS & DF_BIND_NOW
            or bool(tags.get(0x6FFFFFFB, 0) & 0x1)  # DT_FLAGS_1 & DF_1_NOW
        )
        info["BIND_NOW"] = bind_now
        if relro_segment:
            info["RELRO"] = True
            info["RELRO_level"] = "Full RELRO" if bind_now else "Partial RELRO"
        names = {name for name, _value, _typ in self.symbols()}
        info["canary"] = "__stack_chk_fail" in names or "__stack_chk_guard" in names
        return info

    def off_to_vaddr(self, offset: int) -> int | None:
        for p_type, _flags, p_offset, p_vaddr, p_filesz in self.program_headers():
            if p_type == 1 and p_offset <= offset < p_offset + max(p_filesz, 1):
                return p_vaddr + (offset - p_offset)
        return None

    def vaddr_to_off(self, vaddr: int) -> int | None:
        for p_type, _flags, p_offset, p_vaddr, p_filesz in self.program_headers():
            if p_type == 1 and p_vaddr <= vaddr < p_vaddr + max(p_filesz, 1):
                return p_offset + (vaddr - p_vaddr)
        return None


_GADGET_PATTERNS: Final = {
    "pop rdi; ret": b"\x5f\xc3",
    "pop rsi; ret": b"\x5e\xc3",
    "pop rdx; ret": b"\x5a\xc3",
    "pop rax; ret": b"\x58\xc3",
    "syscall; ret": b"\x0f\x05\xc3",
    "leave; ret": b"\xc9\xc3",
    "/bin/sh": b"/bin/sh\x00",
}


# ``e_machine`` -> (capstone arch attribute, decoder family).  The decoder used
# to pick a mode from the ELF *class* alone and always hand it to
# ``CS_ARCH_X86``, so an ARM binary came back as plausible x86 text with no
# warning.  Measured: ``bx lr`` (``1e ff 2f e1``) decoded as
# ``add byte ptr [eax - 0xe11c60], dh`` -- false instructions read as ground
# truth are worse than no instructions.  A machine that is not in this table
# gets no engine at all, and the caller says why.
_CS_ARCH_BY_MACHINE: Final = {
    3: ("CS_ARCH_X86", "x86"),        # EM_386
    62: ("CS_ARCH_X86", "x86"),       # EM_X86_64
    40: ("CS_ARCH_ARM", "arm"),       # EM_ARM
    183: ("CS_ARCH_ARM64", "arm64"),  # EM_AARCH64
}

# Machines whose return instruction is the single byte ``0xC3``.  The gadget
# walk finds ``ret`` sites by that byte, which is an x86 fact.  Giving ARM a
# decoder and still scanning for ``0xC3`` would find no return site and answer
# "no gadget" from a search that never looked for ``bx lr`` -- a new lie in
# place of the old one, so non-x86 keeps the byte-pattern fallback.
_RET_BYTE_MACHINES: Final = (3, 62)

# ``e_machine`` names for the machines a CTF actually ships, so "no decoder for
# this machine" can name the machine instead of printing a bare number.
_MACHINE_NAMES: Final = {
    3: "i386", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "s390",
    40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V",
}


def _capstone_mode(capstone, elf: "_Elf", family: str) -> int:
    big = capstone.CS_MODE_BIG_ENDIAN if elf.endian == ">" else 0
    if family == "x86":
        return capstone.CS_MODE_64 if elf.is64 else capstone.CS_MODE_32
    if family == "arm":
        # Bit 0 of a Thumb code address is set.  The entry point is the only
        # address visible without symbols, so it decides the mode here.
        mode = capstone.CS_MODE_THUMB if elf.e_entry & 1 else capstone.CS_MODE_ARM
        return mode | big
    return capstone.CS_MODE_ARM | big  # arm64 has one mode; 0 also means little-endian


def _decoder_label(elf: "_Elf") -> str:
    """The instruction set that will really be decoded, for the header line."""
    family = _CS_ARCH_BY_MACHINE.get(elf.e_machine, (None, ""))[1]
    if family == "x86":
        return "x86-64" if elf.is64 else "x86-32"
    if family == "arm":
        return "thumb" if elf.e_entry & 1 else "arm"
    if family == "arm64":
        return "aarch64"
    return ""


def _decoder_gap(elf: "_Elf") -> str:
    """Why ``_capstone(elf)`` returned ``None``, phrased for tool output.

    "capstone missing" and "elfpeek has no decoder wired for this machine" are
    different faults with different fixes; reporting the first for the second
    sends the reader after a package that is already installed.  The gap is
    always blamed on *this function's* table, never on capstone: capstone 5
    ships MIPS/PPC/SYSZ/RISC-V/SPARC backends, so "no backend exists" would be
    a false statement about a library that in fact has one.
    """
    try:
        import capstone  # type: ignore  # noqa: F401
    except Exception:  # noqa: BLE001
        return "capstone is not installed in this image"
    if elf.e_machine not in _CS_ARCH_BY_MACHINE:
        named = _MACHINE_NAMES.get(elf.e_machine, "unknown")
        return f"elfpeek has no decoder wired for e_machine=0x{elf.e_machine:x} ({named})"
    label = _decoder_label(elf) or f"e_machine=0x{elf.e_machine:x}"
    return f"capstone could not initialise a {label} decoder"


def _capstone(elf: "_Elf"):
    """Load capstone when present and the machine is known; else ``None``.

    A static import would break the stdlib-only image, so this is dynamic.  The
    degraded path still answers "which offsets do I need", just without
    instruction text.  ``None`` is never a statement about the binary: callers
    say *why* (see ``_decoder_gap``) instead of implying the file has no code.
    """
    try:
        import capstone  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    entry = _CS_ARCH_BY_MACHINE.get(elf.e_machine)
    if entry is None:
        return None
    attr, family = entry
    try:
        return capstone.Cs(getattr(capstone, attr), _capstone_mode(capstone, elf, family))
    except Exception:  # noqa: BLE001
        return None


# Bounds of the decoder walk.  Module level so a caller (or a test) can see
# what the scan is allowed to spend, instead of a magic 4.0 buried in a loop.
_GADGET_BUDGET_S: Final = 4.0
_GADGET_RET_CAP: Final = 2000
_GADGET_PER_NEEDLE: Final = 5


def _gadget_offsets(elf: "_Elf", filt: str, limit: int) -> tuple[list[str], str]:
    """Fixed-pattern scan: answers "where is pop rdi", not "list every gadget".

    Every row comes from ``bytes.find`` over the whole file: no time budget, no
    window, so a "not found" here is a real absence.  The one way this path can
    under-report is the row limit, and that is named in the output rather than
    left to look like "there was nothing else".
    """
    wanted = [token.strip().lower() for token in (filt or "").split("|") if token.strip()]
    # ``binsh`` names the /bin/sh constant, not a gadget: filtering on it would
    # drop every "pop rdi" row the caller also asked for, and the decoder path
    # already treats it as a constant instead of a needle.
    wanted = [token for token in wanted if token not in ("binsh", "/bin/sh")]
    ordered = [
        (label, pattern)
        for label, pattern in _GADGET_PATTERNS.items()
        if not wanted or any(token in label for token in wanted)
    ]
    # One slot is reserved for the /bin/sh row, which is appended from a byte
    # scan below whether or not the row limit reached that pattern.  Without the
    # reservation the same binary answered "pop rdi found, /bin/sh missing" at
    # limit=2 and listed /bin/sh at limit=60 -- a limit, not a fact.
    pattern_room = max(limit - 1, 1)
    rows: list[str] = []
    for index, (label, pattern) in enumerate(ordered):
        if len(rows) >= pattern_room:
            rows.append(
                f"... {len(ordered) - index} of {len(ordered)} pattern(s) not scanned "
                f"(limit={limit})"
            )
            break
        position = elf.data.find(pattern)
        if position < 0:
            rows.append(f"{label:<16} not found")
            continue
        vaddr = elf.off_to_vaddr(position)
        rows.append(
            f"{label:<16} file 0x{position:x}"
            + (f"  vaddr 0x{vaddr:x}" if vaddr is not None else "")
        )
    # Same guarantee as the decoder path: the constant is always answered.
    if not any(row.startswith("/bin/sh") for row in rows):
        position = elf.data.find(b"/bin/sh\x00")
        if position >= 0:
            vaddr = elf.off_to_vaddr(position)
            rows.append(
                "/bin/sh  file 0x%x%s"
                % (position, f"  vaddr 0x{vaddr:x}" if vaddr is not None else "")
            )
        else:
            rows.append("/bin/sh  not found")
    return rows, ""


def _gadgets_capstone(elf: "_Elf", filt: str, limit: int) -> tuple[list[str], str]:
    """Enumerate real instruction boundaries ending in ``ret``, depth <= 5.

    Returns ``(rows, note)``.  ``note`` is non-empty when the walk stopped
    before it was done: a time budget, or a per-segment cap on the number of
    ``ret`` sites.  A truncated walk cannot answer "does this binary have a
    pop rdi" -- it can only answer "I did not reach it" -- so the two answers
    are kept apart instead of being merged into one "not found".
    """
    engine = _capstone(elf)
    if engine is None or elf.e_machine not in _RET_BYTE_MACHINES:
        return [], ""
    tokens = [token.strip().lower() for token in (filt or "").split("|") if token.strip()]
    # ``/bin/sh`` is a constant, not an instruction: the decoder path can never
    # produce it, so keeping it in ``needles`` made the same binary report
    # "pop rdi found" without a decoder and "not found" with one.  It is always
    # listed below, from the byte scan, whatever the filter says.
    wanted = [token for token in tokens if token not in ("binsh", "/bin/sh")]
    needles = wanted or ["rdi", "rsi", "rdx", "syscall"]
    deadline = time.monotonic() + _GADGET_BUDGET_S
    hits: list[str] = []
    counts = {token: 0 for token in needles}
    reasons: list[str] = []

    segments = [
        (seg_offset, seg_vaddr, seg_size)
        for p_type, p_flags, seg_offset, seg_vaddr, seg_size in elf.program_headers()
        if p_type == 1 and p_flags & 1
    ]
    timed_out = False
    for number, (seg_offset, seg_vaddr, seg_size) in enumerate(segments, start=1):
        if time.monotonic() > deadline:
            reasons.append(
                f"the {_GADGET_BUDGET_S:g} s decode budget ran out before segment "
                f"{number} of {len(segments)}"
            )
            break
        blob = elf.data[seg_offset : seg_offset + seg_size]
        rets = [index for index, byte in enumerate(blob) if byte == 0xC3]
        if len(rets) > _GADGET_RET_CAP:
            reasons.append(
                f"segment {number} of {len(segments)} has {len(rets)} ret site(s) and "
                f"only the first {_GADGET_RET_CAP} were decoded"
            )
            rets = rets[:_GADGET_RET_CAP]
        for ret in rets:
            if time.monotonic() > deadline:
                reasons.append(
                    f"the {_GADGET_BUDGET_S:g} s decode budget ran out inside segment "
                    f"{number} of {len(segments)}"
                )
                timed_out = True
                break
            for start in range(max(0, ret - 20), ret):
                try:
                    chain = list(engine.disasm(blob[start : ret + 1], seg_vaddr + start))
                except Exception:  # noqa: BLE001
                    continue
                if not chain or len(chain) > 5:
                    continue
                if sum(item.size for item in chain) != ret + 1 - start:
                    continue
                if chain[-1].mnemonic != "ret":
                    continue
                # Same separator as the fixed-pattern path, so "pop rdi; ret"
                # matches what the model was told to grep for.
                text = "; ".join(
                    item.mnemonic + (" " + item.op_str if item.op_str else "") for item in chain
                )
                for token in needles:
                    if token in text and counts[token] < _GADGET_PER_NEEDLE:
                        counts[token] += 1
                        hits.append(
                            f"{text[:60]:<60} file 0x{seg_offset + start:x}  "
                            f"vaddr 0x{seg_vaddr + start:x}"
                        )
            if timed_out or all(counts[token] >= _GADGET_PER_NEEDLE for token in needles):
                break
        if timed_out or all(counts[token] >= _GADGET_PER_NEEDLE for token in needles):
            break

    stopped = "; ".join(reasons)
    summary: list[str] = []
    for token in needles:
        if counts[token] == 0:
            label = (
                f"pop {token}" if token in ("rdi", "rsi", "rdx", "rax") else token
            )
            if stopped:
                summary.append(f"{label:<16} NOT FOUND IN AN INCOMPLETE SCAN (see the note above)")
            else:
                summary.append(
                    f"{label:<16} not found ({len(segments)} executable segment(s) decoded)"
                )
    # Always answer the one question a ROP chain asks first, whether or not a
    # decoder is installed.  This row is a whole-file byte scan: no budget, so
    # a "not found" here stays honest even when the walk above did not finish.
    position = elf.data.find(b"/bin/sh\x00")
    if position >= 0:
        vaddr = elf.off_to_vaddr(position)
        sh_row = "/bin/sh  file 0x%x%s" % (
            position,
            f"  vaddr 0x{vaddr:x}" if vaddr is not None else "",
        )
    else:
        sh_row = "/bin/sh  not found"

    # The summary and the /bin/sh row are the answer; a truncation marker may
    # not push them out of view.  One slot is reserved for that marker so the
    # row count never exceeds the cap.  The cap is also pulled down to the
    # character window: a row carries the instruction text plus two 0x
    # offsets (~95 chars), and an answer longer than ``_clip``'s budget would
    # get cut at the tail -- the marker would be the thing that disappears,
    # which is exactly the failure this section is about.
    cap = min(max(limit, 8), max((_CLIP_DEFAULT - 1200) // 95, 8))
    tail = summary + [sh_row]
    room = max(cap - len(tail) - 1, 0)
    if len(hits) > room:
        dropped = len(hits) - room
        rows = hits[:room] + [
            f"... {dropped} gadget row(s) not shown (limit={limit}, {cap} rows max)"
        ] + tail
    else:
        rows = hits + tail
    return rows, stopped


def elffind(path: str = "", symbol: str = "", search: str = "") -> str:
    """Resolve an ELF symbol or byte string to both file offset and vaddr.

    Split out of ``elfpeek`` on purpose: these three parameters serve one
    question ("where is system / where is /bin/sh"), and the other six views
    should not carry them in their schema on every call.

    Args:
        path: Binary path.
        symbol: Exact symbol name (e.g. ``system``, ``puts``).
        search: Byte string to locate (e.g. ``/bin/sh``).

    Returns:
        Address/offset pairs, the libc version when one is embedded, and a
        ret2libc readiness note when both ingredients are present.
    """
    target = resolve_path(path)
    if not target.is_file():
        return f"[elffind] not a file: {path!r}."
    data = target.read_bytes()
    try:
        elf = _Elf(data)
    except _NonWebError as exc:
        return str(exc)
    lines: list[str] = []
    if symbol:
        hits = [
            (label, value)
            for label, value, _kind in elf.symbols()
            if label == symbol.strip()
        ]
        if hits:
            for label, value in hits:
                file_offset = elf.vaddr_to_off(value)
                lines.append(
                    f"symbol {label} vaddr 0x{value:x} "
                    + (f"file 0x{file_offset:x}" if file_offset is not None
                       else "(imported: resolved at runtime)")
                )
        else:
            near = [
                label for label, _value, _kind in elf.symbols()
                if symbol.lower() in label.lower()
            ][:10]
            lines.append(
                f"symbol {symbol} not found"
                + (f"; near: {', '.join(near)}" if near
                   else " (symbol table empty or stripped)")
            )
    if search:
        needle = search.encode("latin-1", "replace")
        position = 0
        found: list[str] = []
        while len(found) < 10:
            position = data.find(needle, position)
            if position < 0:
                break
            vaddr = elf.off_to_vaddr(position)
            found.append(
                f"file 0x{position:x}"
                + (f"/vaddr 0x{vaddr:x}" if vaddr is not None else "")
            )
            position += 1
        lines.append(f"string {search!r}: " + (", ".join(found) if found else "not found"))
    if not symbol and not search:
        lines.append("lookup needs symbol=<name> and/or search=<bytes>.")
    version_at = data.find(b"GNU C Library")
    if version_at >= 0:
        head = max(data.rfind(b"\n", 0, version_at), data.rfind(b"\x00", 0, version_at)) + 1
        ends = [
            pos for pos in (data.find(b"\n", version_at), data.find(b"\x00", version_at))
            if pos >= 0
        ]
        tail = min(ends) if ends else len(data)
        lines.append(
            f"libc version: {data[head:tail].decode('latin-1', 'replace').strip()[:120]}"
        )
    names = {label for label, _value, _kind in elf.symbols()}
    if "system" in names and data.find(b"/bin/sh") >= 0:
        lines.append(
            "ret2libc ingredients present: system and /bin/sh are both here -- "
            "leak the base, then compute both from these offsets."
        )
    return _clip("\n".join(lines))


def elfpeek(
    path: str = "",
    view: str = "info",
    limit: int = 60,
    offset: int = 0,
    length: int = 128,
    filt: str = "",
    symbol: str = "",
) -> str:
    """Inspect an ELF binary: info, sections, symbols, strings, gadgets, disasm.

    Args:
        path: Binary path.
        view: info (default) / sections / symbols / strings / gadgets / disasm
            / wide (UTF-16 strings).
        limit: Row cap.
        offset: File start byte for the disasm view.
        length: Byte window for the disasm view.
        filt: Gadget filter, '|'-separated (rdi|syscall|binsh ...).
        symbol: Disasm only -- start at this symbol and stop at the next one.

    Returns:
        A compact table plus a ``next:`` line; when tooling is missing it says
        what to do instead of raising.

    Note:
        Address-to-offset lookups live in ``elffind`` rather than here.  Every
        parameter used by only one view would otherwise be paid for by every
        call of every other view -- the same argument that keeps socket
        schemas off attachment challenges.  ``symbol`` is the deliberate
        exception: ``disasm`` without it cannot read a function at all.
    """
    target = resolve_path(path)
    if not target.is_file():
        return f"[elfpeek] not a file: {path!r}. Run file_triage on the directory first."
    data = target.read_bytes()
    name = (view or "info").strip().lower()

    if name == "wide":
        wide = _Elf.__new__(_Elf)
        wide.data = data
        rows = _Elf.strings(wide, 4, _to_int(limit, 60, 1, 500), True)
        return _clip(
            f"[elfpeek] wide strings: {len(rows)}\n" + ("\n".join(rows) if rows else "(none)")
        )

    try:
        elf = _Elf(data)
    except _NonWebError as exc:
        return str(exc)

    if name == "info":
        security = elf.security()
        entry_segment = "not inside any PT_LOAD (packed or hand-built?)"
        for p_type, p_flags, p_offset, p_vaddr, p_filesz in elf.program_headers():
            if p_type == 1 and p_vaddr <= elf.e_entry < p_vaddr + max(p_filesz, 1):
                entry_segment = (
                    f"PT_LOAD vaddr 0x{p_vaddr:x}..0x{p_vaddr + p_filesz:x} "
                    f"(file 0x{p_offset:x}..0x{p_offset + p_filesz:x}, "
                    f"{'executable' if p_flags & 1 else 'NOT executable -- UPX/packer?'})"
                )
                break
        sections = [row[0] for row in elf.sections() if row[0]]
        names = [row[0] for row in elf.symbols() if row[0] and not row[0].startswith("_")]
        lines = [
            f"[elfpeek] {'64' if elf.is64 else '32'}-bit "
            f"{'LE' if elf.endian == '<' else 'BE'} machine=0x{elf.e_machine:x} "
            f"entry=0x{elf.e_entry:x} size={len(data)} B",
            f"type: {security['type']}, PIE={security['PIE']}",
            f"mitigations: NX={security['NX']} canary={security['canary']} "
            f"RELRO={security['RELRO_level']} "
            f"({_RELRO_NOTE[str(security['RELRO_level'])]})",
            f"entry segment: {entry_segment}",
            f"sections: {', '.join(sections[:24]) or '(none)'}",
            f"symbols (first 30): {', '.join(names[:30]) or '(stripped)'}",
        ]
        if not names:
            lines.append("next: symbol table is empty -- view='strings', then view='gadgets'.")
        elif security["PIE"]:
            lines.append(
                "next: PIE is on, so every address needs the runtime base; look "
                "for a leak first (puts/write@plt on a GOT entry is the usual one)."
            )
        else:
            lines.append(
                "next: no PIE, addresses are fixed -- elffind(symbol='system') "
                "and elffind(search='/bin/sh') give file offset + vaddr."
            )
        return _clip("\n".join(lines))

    if name == "sections":
        rows = [f"{'name':<20}{'addr':>12}{'offset':>12}{'size':>12}"]
        for label, addr, sec_offset, sec_size in elf.sections():
            if label:
                rows.append(f"{label:<20}{hex(addr):>12}{hex(sec_offset):>12}{sec_size:>12}")
        return _clip("\n".join(rows))

    if name == "symbols":
        kinds = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC"}
        rows = [f"{'name':<40}{'value':>12}  type"]
        for label, value, kind in elf.symbols()[: _to_int(limit, 60, 1, 500)]:
            rows.append(f"{label[:40]:<40}{hex(value):>12}  {kinds.get(kind, kind)}")
        if len(rows) == 1:
            rows.append("(symbol table empty -- stripped; use strings/gadgets)")
        return _clip("\n".join(rows))

    if name == "strings":
        rows = elf.strings(4, _to_int(limit, 60, 1, 500))
        return _clip(f"[elfpeek] strings: {len(rows)}\n" + ("\n".join(rows) if rows else "(none)"))

    if name == "gadgets":
        cap_rows = _to_int(limit, 60, 1, 200)
        rows, note = _gadgets_capstone(elf, filt, cap_rows)
        header = "[elfpeek] gadgets (capstone instruction boundaries, depth<=5)"
        if not rows:
            if elf.e_machine in _RET_BYTE_MACHINES:
                why = "no decoder in this image: fixed pattern, first occurrence only"
            else:
                named = _MACHINE_NAMES.get(elf.e_machine, "unknown")
                why = (
                    f"e_machine=0x{elf.e_machine:x} ({named}): the patterns below are "
                    "x86 byte sequences (names are an x86 convention), not this "
                    "machine's instructions; read the code with view='disasm'"
                )
            header = f"[elfpeek] gadget/constant scan ({why})"
            rows, note = _gadget_offsets(elf, filt, cap_rows)
        if elf.security()["PIE"]:
            rows.append("(PIE: vaddr is the link-time address; add the runtime base)")
        lines = [header]
        if note:
            # Above the rows, not below: ``_clip`` cuts the tail, and a caveat
            # that gets cut is a caveat that never happened.
            lines.append(f"scan INCOMPLETE: {note}")
            lines.append(
                'anything "NOT FOUND" below means "this scan did not reach it", '
                'not "the binary lacks it": narrow with filt= (e.g. filt=rdi) or '
                "check the offsets with elffind"
            )
        lines.extend(rows or ["(nothing found)"])
        return _clip("\n".join(lines))

    if name == "disasm":
        start = _to_int(offset, 0, 0, max(0, len(data) - 1))
        span = _to_int(length, 128, 16, 4096)
        row_cap = _to_int(limit, 120, 1, 600)

        # ``symbol=`` answers the question people actually ask: "show me
        # check()".  Without it a call can only say "128 bytes from some
        # offset", which is not how a function gets read -- and the row cap
        # then silently ends mid-function, which reads like "the function ends
        # here".  Resolve first, then bound the window by the *next* symbol.
        symbols = elf.symbols()
        wanted = (symbol or "").strip()
        header = ""
        if wanted:
            starts = sorted(
                (value, label) for label, value, kind in symbols
                if label == wanted and value and kind in (0, 2, 10)
            )
            if not starts:
                names = [label for label, value, _kind in symbols if value and label]
                hint = ", ".join(names[:12]) or "(symbol table is empty)"
                return (
                    f"[elfpeek] no function symbol {wanted!r} in this ELF. "
                    f"Known: {hint}\n"
                    "next: view='symbols' for the full table, or elffind search= "
                    "for a byte string, or disasm with a raw offset."
                )
            base, label = starts[0]
            following = [value for value, other in
                         ((v, l) for l, v, _k in symbols if v and l != label)
                         if value > base]
            stop_vaddr = min(following) if following else base + span
            start = elf.vaddr_to_off(base)
            if start is None:
                return f"[elfpeek] symbol {label!r} is at 0x{base:x}, outside every PT_LOAD"
            span = max(1, min(stop_vaddr - base, 0x4000))
            header = f"symbol {label} at vaddr 0x{base:x}, {span} B (bounded by the next symbol)"

        chunk = data[start : start + span]
        vaddr = elf.off_to_vaddr(start)
        engine = _capstone(elf)
        if engine is None:
            # ``-M intel`` is an x86 flag; objdump rejects it for other machines.
            intel = " -M intel" if elf.e_machine in _RET_BYTE_MACHINES else ""
            return _clip(
                f"[elfpeek] no disassembler available ({_decoder_gap(elf)}), so this "
                "is a byte view -- the bytes below are not instructions:\n"
                f"  objdump -d{intel} --start-address=0x{(vaddr or start):x} "
                f"--stop-address=0x{((vaddr or start) + len(chunk)):x} <file>\n"
                + (header + "\n" if header else "")
                + f"file offset 0x{start:x}, {len(chunk)} B, vaddr "
                + (f"0x{vaddr:x}" if vaddr is not None else "?")
                + f":\n{chunk[:256].hex()}"
            )

        vaddr = vaddr if vaddr is not None else start
        label = _decoder_label(elf)
        rows = [
            "[elfpeek] disasm"
            + (f" {label}" if label else "")
            + " "
            + (header if header else f"file offset 0x{start:x}, {span} B")
            + f", vaddr 0x{vaddr:x}"
            + (" (PIE: add runtime base)" if elf.security()["PIE"] else "")
        ]
        # ``_clip`` cuts the *tail*, and the resume line below is the last
        # line, so the byte budget -- not the row cap alone -- decides where
        # the listing ends.  Letting ``_clip`` make that cut lost the resume
        # line on any real function (a 4 000-character window is ~70 rows
        # against a 600-row cap), and the rows it dropped were still counted
        # in ``emitted``, so the offset it named skipped instructions the
        # reader never saw.  Reserve room for the line and stop before the
        # budget is spent: ``emitted`` is then exactly what was printed.
        reserve = 200  # the resume line, generously
        budget = _CLIP_DEFAULT - reserve
        used = len(rows[0])
        emitted = 0
        stopped_at = None
        hit_budget = False
        for instruction in engine.disasm(chunk, vaddr):
            nearest = ""
            best = None
            for label, value, _kind in symbols:
                if value <= instruction.address and (best is None or value > best):
                    best, nearest = value, label
            if best is not None and instruction.address - best < 0x10000:
                nearest = f"  ; <{nearest}+0x{instruction.address - best:x}>"
            line = (
                f"{instruction.address:08x}  {instruction.bytes.hex()[:20]:<20}"
                f"{instruction.mnemonic:<8}{instruction.op_str}{nearest}"
            )
            # Always print the first row: one over-long line must not turn
            # into "(0 decodable instructions)".
            hit_budget = used + 1 + len(line) > budget
            if emitted and (hit_budget or emitted >= row_cap):
                stopped_at = instruction.address
                break
            rows.append(line)
            used += 1 + len(line)
            emitted += 1
        if emitted == 0:
            rows.append("(0 decodable instructions: offset lands in data; check sections)")
        elif stopped_at is not None and stopped_at < vaddr + len(chunk):
            # Say where to resume.  Ending at the cap without a word is read as
            # "function ends here", and that is how a run concludes the wrong
            # thing about a long check function.  Name the reason too: the
            # output window is what stops a listing at ~70 rows, and telling
            # the reader to "raise limit" there sends it after a knob that
            # cannot help.
            resume = elf.vaddr_to_off(stopped_at)
            where = f"offset=0x{(resume if resume is not None else stopped_at):x}"
            if hit_budget:
                why = (
                    f"{_CLIP_DEFAULT}-char output window"
                    f" (limit={row_cap} rows was not the limit)"
                )
            else:
                why = f"limit={row_cap} rows"
            rows.append(
                f"... truncated at {emitted} instructions ({why}); "
                f"continue with {where}"
            )
        return _clip("\n".join(rows))

    return (
        f"[elfpeek] unknown view {view!r}. Choose info / sections / symbols / "
        "strings / gadgets / disasm / wide; for addresses use elffind."
    )


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------

def _as_async(func):
    """Run a blocking helper off the event loop, keeping its signature.

    ``function_tool(timeout=...)`` is rejected for sync handlers (the SDK
    raises at registration time, which would surface as "every non-web tool
    failed to register" rather than as a timeout).  A thin async wrapper fixes
    that and is also the correct behaviour: unpacking a 64MB archive must not
    freeze the agent's event loop.

    ``functools.wraps`` matters because the SDK derives the JSON schema from
    ``inspect.signature``, which follows ``__wrapped__`` -- without it every
    parameter would disappear from the schema.
    """
    import asyncio
    import functools

    @functools.wraps(func)
    async def runner(*args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    return runner


#: Answers an attachment question.  Registered on ``kind == "file"``.
FILE_TOOLS: Final = (decode_blob, unpack_archive, hexpeek, elfpeek, elffind)
#: Socket primitives, added on top of :data:`FILE_TOOLS` for ``kind == "tcp"``.
#: A remote-binary question almost always ships the binary too: the pwn
#: playbook says "``elffind`` the offset, then send it", so withholding the
#: static tools made the first instruction unexecutable (REVIEW-20261112 PWN-1).
TCP_TOOLS: Final = (tcp, tcp_batch)


def register(register_fn=None, kind: str = "file") -> list[str]:
    """Register the non-web primitives for one challenge kind.

    Args:
        register_fn: Injection point; defaults to
            ``factory.register_agent_tools``.
        kind: ``"file"`` (attachment primitives) or ``"tcp"`` (attachment
            primitives **plus** the socket primitives -- a remote-binary
            challenge needs both).  Anything else registers nothing -- a web
            challenge must not pay for these schemas.

    Returns:
        Tool names registered by this call (empty when already present).
    """
    if kind == "file":
        tools = FILE_TOOLS
    elif kind == "tcp":
        tools = (*FILE_TOOLS, *TCP_TOOLS)
    else:
        return []

    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(tool, "name", "") for tool in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001
            existing = set()
    else:
        existing = set()

    from agents import function_tool

    wrapped = [function_tool(timeout=180)(_as_async(func)) for func in tools]
    fresh = [tool for tool in wrapped if getattr(tool, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [tool.name for tool in fresh]
