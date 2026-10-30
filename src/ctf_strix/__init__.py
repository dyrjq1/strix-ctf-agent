"""CTF-oriented glue on top of strix.

Success criterion for this module: ``session_manager.create_or_reuse`` runs on
the host without Docker, and a command executed through the returned session
produces real output.
"""

from __future__ import annotations

def install() -> None:
    """Register the local sandbox backend.

    ``local_backend`` pulls in ``agents`` / ``strix`` at import time. Keeping the
    import lazy means pure modules (task parsing, flag extraction, the platform
    HTTP client) stay importable without the full runtime installed, which is
    what makes them unit-testable on a bare machine.
    """
    from ctf_strix.local_backend import install as _install

    _install()


__all__ = ["install"]
__version__ = "0.1.0"
