"""
Corsair threat intelligence module.

Provides CVE correlation and threat mapping capabilities.
"""

from .cisa_kev import CISAKEVClient, KEVEntry
from .cve_correlator import CVECorrelator

__all__ = ["CISAKEVClient", "KEVEntry", "CVECorrelator"]
