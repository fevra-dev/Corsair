"""HTTP/3 validation subsystem.

The optional [h3] extra (`pip install corsair-scan[h3]`) installs aioquic.
This package always imports cleanly; H3Auditor degrades gracefully and
emits a single INFO finding when aioquic is unavailable.
"""

# aioquic-gated: only the client requires the [h3] extra.
try:
    from .client import scan_h3  # noqa: F401
    h3_available = True
except ImportError:
    h3_available = False

# H3Auditor is added in Task 6. Re-export only when present.
try:
    from .auditor import H3Auditor  # noqa: F401
    __all__ = ["H3Auditor", "h3_available"]
except ImportError:
    __all__ = ["h3_available"]
