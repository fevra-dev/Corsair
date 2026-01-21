"""
Corsair fingerprinting module.

Provides technology detection through HTTP response analysis.
"""

from .engine import FingerprintEngine
from .signatures import SIGNATURES

__all__ = ["FingerprintEngine", "SIGNATURES"]
