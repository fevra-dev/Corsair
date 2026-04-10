"""
Corsair TLS Auditor module.

Provides TLS/SSL configuration auditing via sslyze (optional dependency).
Install with: pip install corsair-scan[tls]

sslyze is AGPL-3.0 licensed. It is kept as an optional dependency
to preserve Corsair's MIT license.
"""

try:
    import sslyze  # noqa: F401

    TLS_AVAILABLE = True
except ImportError:
    TLS_AVAILABLE = False


def tls_available() -> bool:
    """Check if TLS auditing is available (sslyze installed)."""
    return TLS_AVAILABLE
