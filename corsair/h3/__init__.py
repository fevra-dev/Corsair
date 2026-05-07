"""HTTP/3 validation subsystem.

The optional [h3] extra (`pip install corsair-scan[h3]`) installs aioquic.
This package always imports cleanly; H3Auditor degrades gracefully and
emits a single INFO finding when aioquic is unavailable.

Mirrors the corsair.tls availability pattern: a module-level UPPER_CASE
constant for static checks and a same-name lowercase callable for
runtime use.
"""

__all__ = ["H3_AVAILABLE", "h3_available"]

# aioquic-gated: only the client requires the [h3] extra.
try:
    from .client import scan_h3  # noqa: F401
    H3_AVAILABLE = True
except ImportError:
    H3_AVAILABLE = False


def h3_available() -> bool:
    """Check if HTTP/3 probing is available (aioquic installed)."""
    return H3_AVAILABLE


# H3Auditor is added in Task 6. Re-export only when present.
try:
    from .auditor import H3Auditor  # noqa: F401
    __all__.append("H3Auditor")
except ImportError:
    pass
