"""
Corsair compliance mapping module.

Maps security findings to compliance frameworks.
"""

from .frameworks import COMPLIANCE_FRAMEWORKS, get_framework_requirements

__all__ = ["COMPLIANCE_FRAMEWORKS", "get_framework_requirements"]
