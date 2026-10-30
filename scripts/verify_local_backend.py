"""End-to-end check: strix runs without Docker via the local backend.

Run: PYTHONPATH=src:vendor/src .venv/bin/python scripts/verify_local_backend.py

Passes when:
  1. strix's backend registry contains ``local``
  2. ``session_manager.create_or_reuse`` returns a live session (no Docker)
  3. a command run through that session returns real stdout
"""

from __future__ import annotations

import asyncio
import os
import sys


async def main() -> int:
    os.environ["STRIX_RUNTIME_BACKEND"] = "local"

    from ctf_strix.local_backend import install

    install()

    from strix.runtime import backends, session_manager

    registered = backends.supported_backends()
    print(f"[1] backends: {registered}")
    assert "local" in registered, "local backend not registered"

    bundle = await session_manager.create_or_reuse("verify-1", image="unused", local_sources=[])
    session = bundle["session"]
    print(f"[2] session: {type(session).__name__}")

    result = await session.exec("sh", "-c", "echo strix-local-ok && id -u")
    stdout = result.stdout.decode("utf-8", errors="replace").strip()
    print(f"[3] exec stdout: {stdout!r}")
    assert "strix-local-ok" in stdout, f"unexpected exec output: {stdout!r}"

    # Teardown inside the loop: subprocess transports must close before the
    # loop dies, otherwise asyncio logs a noisy "Event loop is closed".
    await bundle["client"].delete(session)
    await session.aclose()

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
