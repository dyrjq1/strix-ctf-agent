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
import gzip
import html
import io
import lzma
import re
import socket
import struct
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Final
from urllib.parse import unquote

#: Same flag shape as ``flag_extract.FLAG_RE``.  Kept as a literal so this
#: module has no import cycle and can be unit-tested alone.
_FLAG_RE: Final = re.compile(r"(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{[0-9a-zA-Z_\-]{2,}\}")

#: A 10MB "blob" is a file, not a blob.  Saying so costs one line instead of
#: 256k characters of garbage in the context.
_BLOB_MAX_CHARS: Final = 256 * 1024
#: Five independent encodings is already unusual; more means the scoring is
#: chasing its own tail.
_BLOB_MAX_LAYERS: Final = 8

#: Formats ``_sniff`` can name but cannot read.  Used only to turn "nothing
#: extracted" into an actionable message; extraction is never attempted.
_NAMES_ONLY: Final = frozenset({"7z", "rar"})

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


def _clip(text: str, limit: int = 4000) -> str:
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


def _text_variants(text: str) -> list[tuple[str, str]]:
    """Transforms that keep text as text (no encoding layer)."""
    out: list[tuple[str, str]] = []
    rot = codecs.encode(text, "rot13")
    # rot13 is a bijection on ASCII letters, so it always "succeeds"; accept
    # it only when it produces a flag or more English than the input.  Without
    # this gate a plain sentence gets "decoded" into nonsense and the chain
    # records a step that made the text worse.
    if rot != text and (_FLAG_RE.search(rot) or _english_hint(rot) > _english_hint(text)):
        out.append(("rot13", rot))
    url = unquote(text)
    if url != text:
        out.append(("urlencode", url))
    entity = html.unescape(text)
    if entity != text:
        out.append(("html-entity", entity))
    return out


def _decode_candidates(text: str) -> list[tuple[str, str, float]]:
    """Return ``(step name, decoded text, score)`` for plausible decodings.

    Score = printable ratio plus 0.5 for containing a flag.  The 0.85 gate at
    the call site is what stops the chain from "decoding" arbitrary prose.
    """
    found: list[tuple[str, str, float]] = []
    for name, func in (
        ("base64", _as_b64),
        ("base32", _as_b32),
        ("hex", _as_hex),
        ("binary", _as_binary),
    ):
        raw = func(text)
        if raw is None:
            continue
        ratio = _ratio(raw)
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            decoded = raw.decode("latin-1")
        hit = bool(_FLAG_RE.search(decoded))
        if ratio >= 0.85 or hit:
            found.append((name, decoded, ratio + (0.5 if hit else 0.0)))
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

    Handles base64 / base32 / hex / binary, plus rot13 / urlencode / html
    entities between layers.  It walks greedily: at each layer it takes the
    best-scoring candidate above 0.85 printable, the only gate that reliably
    separates "a real next layer" from "noise that happened to decode".

    Args:
        text: The blob or encoded string (file content, pasted token, etc.).
        max_layers: How many nested encodings to peel, 1-8, default 5.

    Returns:
        The chain (``base64 -> hex``), the flag if one appeared, the first 200
        chars of the result, and one line per layer so a wrong turn is visible.
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
    chain: list[str] = []
    steps: list[str] = []
    hit = ""

    for _ in range(layers):
        candidates = _decode_candidates(current)
        if not candidates:
            break
        candidates.sort(key=lambda item: item[2], reverse=True)
        name, decoded, score = candidates[0]
        if score < 0.85:
            break
        chain.append(name)
        steps.append(f"L{len(chain)} {name} -> {decoded[:80]!r}")
        current = decoded.strip()
        match = _FLAG_RE.search(current)
        if match:
            hit = match.group(0)
            break

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
    if not hit:
        parts.append(
            "next: no flag yet -- if the result is short and unreadable, raise "
            "max_layers; if it is text but wrong, try the runner-up candidate "
            "(a wrong first pick is the usual failure)."
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
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    # 7z and RAR are *named* but deliberately not extracted: Python's stdlib
    # has no reader for either and this image ships no 7z/rar binary.  Naming
    # them matters because "detected unknown, nothing extracted" reads exactly
    # like a corrupt file -- the model then retries unpack_archive instead of
    # changing method.  A RAR self-extracting stub can precede the signature by
    # up to 64 KB (rarlab technote), so search that window rather than byte 0.
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


def _unique_dir(base: Path) -> Path:
    """Never mix this extraction into a previous run's output."""
    if not base.exists():
        return base
    index = 1
    while (base.parent / f"{base.name}-{index}").exists():
        index += 1
    return base.parent / f"{base.name}-{index}"


def _signature_offset(path: Path, kind: str) -> int:
    """Where the named-only signature actually starts (0 when it is the header).

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
    source = Path(path).expanduser()
    if not source.is_file():
        return (
            f"[unpack_archive] not a file: {path!r}\n"
            "next: list the directory first (`ls -la`) -- attachments are often "
            "given a name different from the one in the statement."
        )
    depth_cap = _to_int(max_depth, 3, 1, 5)
    root = _unique_dir(Path(out_dir or "extracted"))
    root.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    skipped: list[str] = []
    produced: list[Path] = []
    budget = {"bytes": 0, "files": 0}

    def walk(item: Path, depth: int, kind: str | None = None) -> None:
        if kind is None:
            kind = _sniff(item)
        if not kind or depth > depth_cap:
            return
        if kind in _NAMES_ONLY:
            # Recognized but unreadable here.  Stop before _from_stream, which
            # would otherwise raise KeyError on the opener table.
            return
        sub = root if depth == 1 else root / f"_d{depth}"
        sink = _Sink(sub, budget)
        try:
            if kind == "zip":
                _from_zip(item, sink)
            elif kind == "tar":
                _from_tar(item, sink)
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
        if kind in _NAMES_ONLY:
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
    target = Path(path).expanduser()
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
    except OSError as exc:
        raise _NonWebError(
            f"[tcp] cannot connect to {host}:{port} ({type(exc).__name__}: {exc}). "
            "next: confirm the port from the task statement; a refused port on a "
            "running box usually means the wrong port, not a dead box."
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
            "next: retry with tls=false -- plain TCP on 443 is common in CTF."
        ) from None


def _drain(sock: socket.socket, expect: bytes | None, read_timeout: float, cap: int) -> bytes:
    """Read until ``expect`` appears, the peer closes, or the window expires."""
    buffer = b""
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
            break
        buffer += chunk
        if expect and expect in buffer:
            break
        if time.monotonic() > deadline:
            break
    return buffer


def _render(data: bytes, label: str, hex_limit: int = 256) -> str:
    if not data:
        return f"{label}: (empty)"
    text = "".join(
        chr(byte) if 32 <= byte < 127
        else ("\\n" if byte == 10 else ("\\r" if byte == 13 else "."))
        for byte in data[:600]
    )
    return f"{label} {len(data)} B\n  hex: {data[:hex_limit].hex()}\n  ascii: {text}"


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
    try:
        sock = _connect(host, target_port, min(10.0, window + 7.0), bool(tls), sni)
        try:
            # Grab the banner first: many services print a prompt and then
            # wait, so sending immediately would bury the prompt in our echo.
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
                    return f"[tcp] send failed: {exc}. The peer closed after the banner."
            expect_bytes = expect.encode("utf-8", "surrogateescape") if expect else None
            body = _drain(sock, expect_bytes, window, cap)
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except _NonWebError as exc:
        return str(exc)

    elapsed_ms = (time.time() - started) * 1000
    parts = [
        f"[tcp] {host}:{target_port} connected in {elapsed_ms:.0f} ms "
        f"(sent {len(raw)} B, tls={bool(tls)})"
    ]
    if banner:
        parts.append(_render(banner, "banner"))
    if body:
        parts.append(_render(body, "reply"))
    elif not banner:
        parts.append("no bytes received -- the service is waiting for input first.")
    if expect:
        parts.append("expect: MATCHED" if expect.encode() in body else "expect: not found")
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
        Header, then ``#i sent N B -> recv M B hex=... ascii=...`` per payload,
        so a differing response is visible without reading 200 bodies.
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
                body = _drain(sock, None, window, cap)
                preview = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in body[:60])
                rows.append(
                    f"#{index} sent {len(raw)} B -> recv {len(body)} B "
                    f"hex={body[:48].hex()} ascii={preview!r}"
                )
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
    tail = (
        "next: compare the 'recv' column, not the hex. The candidate whose "
        "length or first bytes differ is the signal; if every line is identical, "
        "the hypothesis is wrong -- change the question, not the payload."
    )
    return _clip("\n".join([head] + rows + [tail]))

# ---------------------------------------------------------------------------
# 6. elfpeek -- enough ELF to decide the next move
# ---------------------------------------------------------------------------


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
        }
        for p_type, p_flags, _offset, _vaddr, _filesz in self.program_headers():
            if p_type == 0x6474E551:  # PT_GNU_STACK
                info["NX"] = not (p_flags & 1)
            if p_type == 0x6474E552:  # PT_GNU_RELRO
                info["RELRO"] = True
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


def _capstone(elf: "_Elf"):
    """Load capstone when present; ``None`` means the caller degrades.

    A static import would break the stdlib-only image, so this is dynamic.  The
    degraded path still answers "which offsets do I need", just without
    instruction text.
    """
    try:
        import capstone  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    try:
        mode = capstone.CS_MODE_64 if elf.is64 else capstone.CS_MODE_32
        return capstone.Cs(capstone.CS_ARCH_X86, mode)
    except Exception:  # noqa: BLE001
        return None


def _gadget_offsets(elf: "_Elf", filt: str, limit: int) -> list[str]:
    """Fixed-pattern scan: answers "where is pop rdi", not "list every gadget"."""
    wanted = [token.strip().lower() for token in (filt or "").split("|") if token.strip()]
    # ``binsh`` names the /bin/sh constant, not a gadget: filtering on it would
    # drop every "pop rdi" row the caller also asked for, and the decoder path
    # already treats it as a constant instead of a needle.
    wanted = [token for token in wanted if token not in ("binsh", "/bin/sh")]
    rows: list[str] = []
    for label, pattern in _GADGET_PATTERNS.items():
        if wanted and not any(token in label for token in wanted):
            continue
        position = elf.data.find(pattern)
        if position < 0:
            rows.append(f"{label:<16} not found")
            continue
        vaddr = elf.off_to_vaddr(position)
        rows.append(
            f"{label:<16} file 0x{position:x}"
            + (f"  vaddr 0x{vaddr:x}" if vaddr is not None else "")
        )
        if len(rows) >= limit:
            break
    return rows


def _gadgets_capstone(elf: "_Elf", filt: str, limit: int) -> list[str]:
    """Enumerate real instruction boundaries ending in ``ret``, depth <= 5."""
    engine = _capstone(elf)
    if engine is None or elf.e_machine not in (3, 62):
        return []
    tokens = [token.strip().lower() for token in (filt or "").split("|") if token.strip()]
    # ``/bin/sh`` is a constant, not an instruction: the decoder path can never
    # produce it, so keeping it in ``needles`` made the same binary report
    # "pop rdi found" without a decoder and "not found" with one.  It is always
    # listed below, from the byte scan, whatever the filter says.
    wanted = [token for token in tokens if token not in ("binsh", "/bin/sh")]
    needles = wanted or ["rdi", "rsi", "rdx", "syscall"]
    deadline = time.monotonic() + 4.0
    rows: list[str] = []
    counts = {token: 0 for token in needles}

    for p_type, p_flags, seg_offset, seg_vaddr, seg_size in elf.program_headers():
        if not (p_type == 1 and p_flags & 1):
            continue
        blob = elf.data[seg_offset : seg_offset + seg_size]
        rets = [index for index, byte in enumerate(blob) if byte == 0xC3][:2000]
        for ret in rets:
            if time.monotonic() > deadline:
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
                    if token in text and counts[token] < 5:
                        counts[token] += 1
                        rows.append(f"{text[:60]:<60} file 0x{seg_offset + start:x}  "
                                    f"vaddr 0x{seg_vaddr + start:x}")
            if all(counts[token] >= 5 for token in needles):
                break
        if all(counts[token] >= 5 for token in needles) or time.monotonic() > deadline:
            break

    for token in needles:
        if counts[token] == 0:
            rows.append(f"{('pop ' + token) if token in ('rdi', 'rsi', 'rdx', 'rax') else token:<60} not found")
    # Always answer the one question a ROP chain asks first, whether or not a
    # decoder is installed.
    position = elf.data.find(b"/bin/sh\x00")
    if position >= 0:
        vaddr = elf.off_to_vaddr(position)
        rows.append(
            "/bin/sh  file 0x%x%s" % (position, f"  vaddr 0x{vaddr:x}" if vaddr is not None else "")
        )
    else:
        rows.append("/bin/sh  not found")
    return rows[: max(limit, 8)]


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
    target = Path(path).expanduser()
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
    target = Path(path).expanduser()
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
            f"RELRO={security['RELRO']}",
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
                "next: no PIE, addresses are fixed -- view='lookup' for "
                "symbol='system' and search='/bin/sh'."
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
        rows = _gadgets_capstone(elf, filt, _to_int(limit, 60, 1, 200))
        header = "[elfpeek] gadgets (capstone instruction boundaries, depth<=5)"
        if not rows:
            header = (
                "[elfpeek] gadget/constant scan (no capstone or non-x86: fixed "
                "pattern, first occurrence only)"
            )
            rows = _gadget_offsets(elf, filt, _to_int(limit, 60, 1, 200))
        if elf.security()["PIE"]:
            rows.append("(PIE: vaddr is the link-time address; add the runtime base)")
        return _clip("\n".join([header] + (rows or ["(nothing found)"])))

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
            return _clip(
                "[elfpeek] no disassembler available (capstone missing), so this is "
                "a byte view. Run the instruction decoder the image does have:\n"
                f"  objdump -d -M intel --start-address=0x{(vaddr or start):x} "
                f"--stop-address=0x{((vaddr or start) + len(chunk)):x} <file>\n"
                + (header + "\n" if header else "")
                + f"file offset 0x{start:x}, {len(chunk)} B, vaddr "
                + (f"0x{vaddr:x}" if vaddr is not None else "?")
                + f":\n{chunk[:256].hex()}"
            )

        vaddr = vaddr if vaddr is not None else start
        rows = [
            f"[elfpeek] disasm "
            + (header if header else f"file offset 0x{start:x}, {span} B")
            + f", vaddr 0x{vaddr:x}"
            + (" (PIE: add runtime base)" if elf.security()["PIE"] else "")
        ]
        emitted = 0
        stopped_at = None
        for instruction in engine.disasm(chunk, vaddr):
            nearest = ""
            best = None
            for label, value, _kind in symbols:
                if value <= instruction.address and (best is None or value > best):
                    best, nearest = value, label
            if best is not None and instruction.address - best < 0x10000:
                nearest = f"  ; <{nearest}+0x{instruction.address - best:x}>"
            rows.append(
                f"{instruction.address:08x}  {instruction.bytes.hex()[:20]:<20}"
                f"{instruction.mnemonic:<8}{instruction.op_str}{nearest}"
            )
            emitted += 1
            if emitted >= row_cap:
                stopped_at = instruction.address + instruction.size
                break
        if emitted == 0:
            rows.append("(0 decodable instructions: offset lands in data; check sections)")
        elif stopped_at is not None and stopped_at < vaddr + len(chunk):
            # Say where to resume.  Ending at the cap without a word is read as
            # "function ends here", and that is how a run concludes the wrong
            # thing about a long check function.
            resume = elf.vaddr_to_off(stopped_at)
            rows.append(
                f"... truncated at {emitted} instructions; continue with "
                f"offset=0x{(resume if resume is not None else stopped_at):x} "
                f"or raise limit (max 600)"
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
#: Answers a remote-service question.  Registered on ``kind == "tcp"``.
TCP_TOOLS: Final = (tcp, tcp_batch)


def register(register_fn=None, kind: str = "file") -> list[str]:
    """Register the non-web primitives for one challenge kind.

    Args:
        register_fn: Injection point; defaults to
            ``factory.register_agent_tools``.
        kind: ``"file"`` (attachment primitives) or ``"tcp"`` (socket
            primitives).  Anything else registers nothing -- a web challenge
            must not pay for these schemas.

    Returns:
        Tool names registered by this call (empty when already present).
    """
    if kind == "file":
        tools = FILE_TOOLS
    elif kind == "tcp":
        tools = TCP_TOOLS
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
