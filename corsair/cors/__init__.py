"""
Corsair CORS DAST module.

Dynamic Application Security Testing for CORS misconfigurations.
Detects arbitrary-origin reflection, null-origin trust, wildcard+credentials,
and (in later waves) subdomain bypass, preflight divergence, and CDN
cache-key poisoning.

Safe by default: no state-changing probes, no credentialed probes,
no traffic to internal networks.
"""

from .auditor import CORSAuditor

__all__ = ["CORSAuditor"]
