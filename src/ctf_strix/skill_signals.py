"""Keyword evidence for deterministic discipline routing.

Single source shared by ``skill_router.skill_route`` (the scorer) and
``tests/test_skill_router.py`` (the consistency gate). The categories are the
same twelve directions ``routing.ROUTES`` renders into the prompt; the test
asserts that alignment so the table can never drift from what the prompt
promises.

A pattern must stay confirmable by looking once -- routing.py's own bar for a
signal. Broad topic words (``web``, ``binary``, ``file``) never appear alone:
every pattern names a mechanism, a file format, an error string or a protocol
token the model can point at in its observations. Anything vaguer belongs to
the direction index, not to routing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class Signal:
    """One direction, its evidence patterns, and where to start reading.

    ``card`` is a file under ``<ref_root>/<category>/`` that names the first
    concrete method for the matched mechanism. Categories whose pack ships a
    single index file point at that index as the card.
    """

    category: str
    patterns: tuple[re.Pattern[str], ...]
    card: str


def _rx(*sources: str) -> tuple[re.Pattern[str], ...]:
    """Compile case-insensitive patterns; declaration order = display order."""
    return tuple(re.compile(s, re.IGNORECASE) for s in sources)


#: Evidence table, ordered like ``routing.ROUTES`` for reviewability.
SIGNALS: Final[tuple[Signal, ...]] = (
    # ctf-web: one row per mechanism family, each with its own start card.
    Signal(
        "ctf-web",
        _rx(
            r"\bsql ?injection\b",
            r"\bsqli\b",
            r"\bsqlmap\b",
            r"union\s+select\b",
            r"\bsqlite error\b",
            r"\bmysql error\b",
            r"\bpostgres(ql)? error\b",
        ),
        "sql-injection.md",
    ),
    Signal(
        "ctf-web",
        _rx(r"\bjwt\b", r"json web token", r"\bjwks\b", r"\bjku\b", r"alg.{0,6}none"),
        "auth-jwt.md",
    ),
    Signal(
        "ctf-web",
        _rx(
            r"\bidor\b",
            r"broken access control",
            r"access[- ]control",
            r"mass assignment",
            r"horizontal privilege",
            r"403 forbidden",
        ),
        "auth-and-access.md",
    ),
    Signal(
        "ctf-web",
        _rx(
            r"\bdeserializ",
            r"\bpickle\b",
            r"yaml\.load",
            r"\bmarshal\b",
            r"java (serialized|serialization fingerprint)",
        ),
        "server-side-deser.md",
    ),
    Signal(
        "ctf-web",
        _rx(
            r"\bssti\b",
            r"template injection",
            r"\bjinja2?\b",
            r"\btwig\b",
            r"freemarker",
        ),
        "server-side-exec.md",
    ),
    Signal(
        "ctf-web",
        _rx(
            r"\bxxe\b",
            r"xml external entity",
            r"\bssrf\b",
            r"gopher://",
            r"php://filter",
            r"path traversal",
        ),
        "server-side.md",
    ),
    Signal(
        "ctf-web",
        _rx(
            r"\bxss\b",
            r"cross[- ]site scripting",
            r"dom clobbering",
            r"content[- ]security[- ]policy",
        ),
        "client-side.md",
    ),
    Signal(
        "ctf-web",
        _rx(r"prototype pollution", r"__proto__", r"\bnode\.?js\b", r"\bexpress\b"),
        "node-and-prototype.md",
    ),
    Signal(
        "ctf-web",
        _rx(r"\bcve-\d{4}-\d+\b", r"known vulnerability.{0,60}version"),
        "cves.md",
    ),
    # ctf-supply-chain: single-index category, the index is the card.
    Signal(
        "ctf-supply-chain",
        _rx(
            r"package(-lock)?\.json",
            r"yarn\.lock",
            r"requirements\.txt",
            r"poetry\.lock",
            r"setup\.(py|cfg)",
        ),
        "ctf-supply-chain.md",
    ),
    Signal(
        "ctf-supply-chain",
        _rx(
            r"typosquat",
            r"dependency confusion",
            r"namespace confusion",
            r"registry (mirror|config|token)",
            r"install (script|hook)",
        ),
        "ctf-supply-chain.md",
    ),
    # ctf-agentic-ai: single-index category.
    Signal(
        "ctf-agentic-ai",
        _rx(
            r"prompt injection",
            r"system prompt",
            r"jailbreak",
            r"guardrail",
            r"moderation",
        ),
        "ctf-agentic-ai.md",
    ),
    Signal(
        "ctf-agentic-ai",
        _rx(
            r"tool (call|use)s?\b",
            r"function call",
            r"agent (loop|memory|state)",
            r"\bmcp\b",
        ),
        "ctf-agentic-ai.md",
    ),
    # ctf-ai-ml
    Signal(
        "ctf-ai-ml",
        _rx(
            r"adversarial (example|perturbation|input)",
            r"data poisoning",
            r"model (inversion|stealing|extraction)",
        ),
        "adversarial-ml.md",
    ),
    Signal(
        "ctf-ai-ml",
        _rx(
            r"\.safetensors\b",
            r"\.onnx\b",
            r"\.pth\b",
            r"model weights",
            r"\bclassifier\b.{0,40}(threshold|decision boundary)",
        ),
        "model-attacks.md",
    ),
    Signal(
        "ctf-ai-ml",
        _rx(r"\bllm\b", r"chat ?bot", r"\bgpt\b", r"prompt.{0,20}(leak|guard)"),
        "llm-attacks.md",
    ),
    # ctf-ai-infra: single-index category.
    Signal(
        "ctf-ai-infra",
        _rx(
            r"\bollama\b",
            r"\bvllm\b",
            r"\bgradio\b",
            r"comfyui",
            r"open[- ]?webui",
            r":11434",
            r":7860",
        ),
        "ctf-ai-infra.md",
    ),
    Signal(
        "ctf-ai-infra",
        _rx(
            r"inference (server|endpoint|api)",
            r"model registry",
            r"gpu (cluster|utilization)",
        ),
        "ctf-ai-infra.md",
    ),
    # ctf-pwn
    Signal(
        "ctf-pwn",
        _rx(
            r"stack (buffer )?overflow",
            r"off[- ]by[- ]one",
            r"ret2(libc|win|plt)",
            r"canary.{0,30}(leak|bypass)",
        ),
        "overflow-basics.md",
    ),
    Signal(
        "ctf-pwn",
        _rx(r"format string", r"%\d+\$[pns]"),
        "format-string.md",
    ),
    Signal(
        "ctf-pwn",
        _rx(
            r"\btcache\b",
            r"\bfastbin\b",
            r"unsorted bin",
            r"house of \w+",
            r"heap (overflow|corruption|grooming|layout)",
        ),
        "heap-techniques.md",
    ),
    Signal(
        "ctf-pwn",
        _rx(r"\brop\b", r"\bgadget", r"shellcode", r"\bsrop\b", r"\bmprotect\b"),
        "rop-and-shellcode.md",
    ),
    Signal(
        "ctf-pwn",
        _rx(r"\bseccomp\b", r"sandbox ?escape", r"\borw\b"),
        "sandbox-escape.md",
    ),
    Signal(
        "ctf-pwn",
        _rx(
            r"kernel (pwn|exploit|module|driver)",
            r"\binitrd\b",
            r"commit_creds",
            r"/dev/(mem|kmem)",
        ),
        "kernel.md",
    ),
    Signal(
        "ctf-pwn",
        _rx(r"checksec", r"\brelro\b", r"\bgot\b.{0,15}(overwrite|entry)", r"\bplt\b"),
        "attack-playbook.md",
    ),
    # ctf-reverse
    Signal(
        "ctf-reverse",
        _rx(
            r"\bstripped\b",
            r"\bupx\b",
            r"anti[- ]?debug",
            r"ptrace.{0,20}(deny|block|fail)",
            r"packed (binary|executable)",
        ),
        "anti-analysis.md",
    ),
    Signal(
        "ctf-reverse",
        _rx(
            r"\.pyc\b",
            r"python bytecode",
            r"pyinstaller",
            r"uncompyle",
            r"\bnuitka\b",
        ),
        "languages-compiled.md",
    ),
    Signal(
        "ctf-reverse",
        _rx(r"\bapk\b", r"\bdex\b", r"\bjadx\b", r"\bwasm\b", r"\bfrida\b"),
        "languages-platforms.md",
    ),
    Signal(
        "ctf-reverse",
        _rx(r"\bz3\b", r"symbolic (execution|solver)", r"smt solver", r"constraint solver"),
        "patterns.md",
    ),
    Signal(
        "ctf-reverse",
        _rx(
            r"obfuscated (code|script|python|javascript)",
            r"vm ?protect",
            r"control[- ]flow flattening",
            r"white[- ]?box",
        ),
        "patterns-runtime.md",
    ),
    # ctf-forensics
    Signal(
        "ctf-forensics",
        _rx(r"\bpcap\b", r"\bwireshark\b", r"\btshark\b", r"network (capture|traffic|forensics)"),
        "network.md",
    ),
    Signal(
        "ctf-forensics",
        _rx(
            r"memory (dump|image|forensics|acquisition)",
            r"\bvolatility\b",
            r"\bvmem\b",
            r"hiberfil",
        ),
        "disk-and-memory.md",
    ),
    Signal(
        "ctf-forensics",
        _rx(
            r"file (carve|carving|recovery)",
            r"\bphotorec\b",
            r"deleted (file|files|entry)",
            r"unallocated",
            r"\be01\b",
        ),
        "disk-recovery.md",
    ),
    Signal(
        "ctf-forensics",
        _rx(
            r"\bstego\b",
            r"steganography",
            r"\blsb\b",
            r"steghide",
            r"\bzsteg\b",
            r"least significant bit",
        ),
        "steganography.md",
    ),
    Signal(
        "ctf-forensics",
        _rx(r"\bexif\b", r"image metadata", r"metadata (strip|extract|forensics)"),
        "stego-image.md",
    ),
    Signal(
        "ctf-forensics",
        _rx(
            r"registry hive",
            r"event log",
            r"\$mft\b",
            r"\bntfs\b",
            r"windows (artifact|registry|prefetch)",
        ),
        "windows.md",
    ),
    # ctf-crypto
    Signal(
        "ctf-crypto",
        _rx(r"\brsa\b", r"\boael\b", r"\bwiener\b", r"\bhastad\b", r"\bcoppersmith\b"),
        "rsa-attacks.md",
    ),
    Signal(
        "ctf-crypto",
        _rx(r"\becc\b", r"elliptic", r"\becdsa\b", r"curve25519", r"\bsecp\d+\b"),
        "ecc-attacks.md",
    ),
    Signal(
        "ctf-crypto",
        _rx(r"lattice", r"\blwe\b", r"knapsack", r"hidden number problem", r"shortest vector"),
        "lattice-and-lwe.md",
    ),
    Signal(
        "ctf-crypto",
        _rx(r"\bprng\b", r"mt19937", r"mersenne twister", r"\blcg\b", r"random seed"),
        "prng-attacks.md",
    ),
    Signal(
        "ctf-crypto",
        _rx(
            r"\baes\b",
            r"\bdes\b",
            r"\brc4\b",
            r"chacha",
            r"\becb\b",
            r"padding oracle",
            r"block cipher",
        ),
        "modern-ciphers.md",
    ),
    Signal(
        "ctf-crypto",
        _rx(r"caesar", r"vigenere", r"substitution cipher", r"playfair", r"frequency analysis"),
        "classic-ciphers.md",
    ),
    Signal(
        "ctf-crypto",
        _rx(r"length extension", r"\bmd5\b", r"\bsha-?1\b", r"hash collision"),
        "router-tables.md",
    ),
    # ctf-misc
    Signal(
        "ctf-misc",
        _rx(
            r"pyjail",
            r"python sandbox",
            r"audit hook",
            r"restricted eval",
            r"__builtins__",
        ),
        "pyjails.md",
    ),
    Signal(
        "ctf-misc",
        _rx(r"bashjail", r"\brbash\b", r"restricted shell", r"shell escape"),
        "bashjails.md",
    ),
    Signal(
        "ctf-misc",
        _rx(
            r"encoding chain",
            r"nested (base64|encoding|decode)",
            r"\brot13\b",
            r"decode.{0,20}(chain|layer)",
        ),
        "encodings.md",
    ),
    Signal(
        "ctf-misc",
        _rx(r"brainfuck", r"esolang", r"\book\b", r"whitespace lang"),
        "games-and-vms.md",
    ),
    Signal(
        "ctf-misc",
        _rx(r"dns (txt|record)", r"\bdig\b", r"subdomain.{0,30}(enumerat|brute)"),
        "dns.md",
    ),
    Signal(
        "ctf-misc",
        _rx(r"spectrogram", r"\.wav\b", r"\.flac\b", r"audio (stego|hidden|secret)"),
        "audio.md",
    ),
    # ctf-malware
    Signal(
        "ctf-malware",
        _rx(r"\bc2\b", r"\bbeacon\b", r"botnet", r"implant", r"c2 (server|channel|config)"),
        "c2-and-protocols.md",
    ),
    Signal(
        "ctf-malware",
        _rx(
            r"import table",
            r"\bpe header\b",
            r"\.net assembly",
            r"\bilspy\b",
            r"\bdnspy\b",
        ),
        "pe-and-dotnet.md",
    ),
    Signal(
        "ctf-malware",
        _rx(
            r"vba macro",
            r"\bole\b",
            r"\bdocm\b",
            r"powershell -enc",
            r"obfuscated (script|macro)",
        ),
        "scripts-and-obfuscation.md",
    ),
    # ctf-osint
    Signal(
        "ctf-osint",
        _rx(
            r"geolocation",
            r"street view",
            r"coordinates",
            r"\bgps\b",
            r"exif.{0,30}gps",
        ),
        "geolocation-and-media.md",
    ),
    Signal(
        "ctf-osint",
        _rx(r"social media", r"username (search|lookup|osint)", r"profile (photo|picture)"),
        "social-media.md",
    ),
    Signal(
        "ctf-osint",
        _rx(r"\bwhois\b", r"\bshodan\b", r"dns history", r"subdomain takeover"),
        "web-and-dns.md",
    ),
)
