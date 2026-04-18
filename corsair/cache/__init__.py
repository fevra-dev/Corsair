"""
Corsair Web Cache Poisoning Detection module.

Detects cache poisoning vulnerabilities through passive header analysis
and active canary injection probing. No optional dependencies required.
"""

from .auditor import CacheAuditor

__all__ = ["CacheAuditor"]
