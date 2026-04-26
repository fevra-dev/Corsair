"""
Web cache poisoning finding definitions.

All cache-related findings that the CacheAuditor can produce.
Each finding uses the existing Finding dataclass with HeaderCategory.CACHING.
"""

import copy
from typing import Optional

from ..models import (
    ComplianceMapping,
    CVECorrelation,
    Finding,
    HeaderCategory,
    Severity,
)


def _compliance(framework: str, req_id: str, req_name: str, status: str = "FAIL"):
    return ComplianceMapping(
        framework=framework,
        requirement_id=req_id,
        requirement_name=req_name,
        status=status,
    )


def _cwe(cwe_id: str, desc: str):
    return CVECorrelation(
        cve_id=cwe_id,
        cvss_score=0.0,
        description=desc,
    )


_OWASP_A05 = _compliance("OWASP_TOP_10_2025", "A05", "Security Misconfiguration")
_PCI_6_2 = _compliance("PCI_DSS_4_0", "6.2", "Secure Development")
_CWE_525 = _cwe("CWE-525", "Information Exposure Through Browser Caching")
_CWE_444 = _cwe("CWE-444", "Inconsistent Interpretation of HTTP Requests")

_REF_URL = "https://portswigger.net/research/practical-web-cache-poisoning"

# -- Passive findings --------------------------------------------------------

_WCP_NOT_CACHED = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.PASS,
    title="Target is not cached",
    description="No caching layer was detected. The target is not vulnerable to web cache poisoning.",
    current_value=None,
    recommendation="No action required.",
    example_value="N/A",
    reference_url=_REF_URL,
)

_WCP_CDN_DETECTED = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.INFO,
    title="CDN/cache layer detected",
    description="A caching layer was detected in front of the target. This is informational and indicates cache poisoning testing is relevant.",
    current_value=None,
    recommendation="Ensure cache configuration follows security best practices.",
    example_value="Vary: Origin, Accept-Encoding",
    reference_url=_REF_URL,
)

_WCP_PERMISSIVE_CACHE_CONTROL = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.LOW,
    title="Overly permissive cache TTL",
    description="The cached response has a very long TTL (max-age or s-maxage > 86400 seconds) without no-store or private directives. Long TTLs amplify the impact of any cache poisoning vulnerability.",
    current_value=None,
    recommendation="Reduce cache TTL or add Cache-Control: private for sensitive content.",
    example_value="Cache-Control: public, max-age=3600",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_525],
)

_WCP_NO_VARY_ORIGIN = Finding(
    header="Vary",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="Missing Vary: Origin on CORS-enabled cached response",
    description="The response includes Access-Control-Allow-Origin but the Vary header does not include Origin. This allows cache poisoning where a CORS response for one origin is served to requests from a different origin.",
    current_value=None,
    recommendation="Add Origin to the Vary header when Access-Control-Allow-Origin varies by request.",
    example_value="Vary: Origin, Accept-Encoding",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_525],
)

_WCP_CACHE_PUBLIC_SENSITIVE = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="Public caching of authenticated content",
    description="The response has Cache-Control: public but also sets Set-Cookie, indicating authenticated or personalized content is being publicly cached. Other users may receive cached responses containing session data.",
    current_value=None,
    recommendation="Use Cache-Control: private or no-store for responses that set cookies.",
    example_value="Cache-Control: private, no-store",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_525],
)

_WCP_NO_CACHE_KEY_QS = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="Query string excluded from cache key",
    description="The cache does not include the query string in its cache key. Any reflected XSS via query parameters becomes stored XSS through the cache, affecting all users.",
    current_value=None,
    recommendation="Configure the cache to include the full query string in the cache key.",
    example_value="Cache key includes: method + host + path + query string",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

# -- Active findings: unkeyed header reflection ------------------------------

_WCP_UNKEYED_HEADER_CRITICAL = Finding(
    header="X-Forwarded-Host",
    category=HeaderCategory.CACHING,
    severity=Severity.CRITICAL,
    title="Critical cache poisoning via unkeyed header",
    description="An unkeyed request header is reflected in a security-critical context (script import or CSP header) of a cached response. An attacker can poison the cache to serve malicious scripts or weaken security policies for all users.",
    current_value=None,
    recommendation="Add the reflected header to the cache key, or strip it at the CDN/proxy layer before it reaches the application.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_UNKEYED_HEADER_HIGH = Finding(
    header="X-Forwarded-Host",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="High-risk cache poisoning via unkeyed header",
    description="An unkeyed request header is reflected in a high-risk context (redirect, stylesheet, CORS header, or JavaScript variable) of a cached response. An attacker can poison the cache to redirect users, inject CSS, or manipulate client-side logic.",
    current_value=None,
    recommendation="Add the reflected header to the cache key, or strip it at the CDN/proxy layer.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_UNKEYED_HEADER_MEDIUM = Finding(
    header="X-Forwarded-Host",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="Moderate cache poisoning via unkeyed header",
    description="An unkeyed request header is reflected in a moderate-risk context (canonical link or image/iframe source) of a cached response. This enables SEO poisoning or content injection attacks.",
    current_value=None,
    recommendation="Add the reflected header to the cache key, or strip it at the CDN/proxy layer.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)

_WCP_UNKEYED_HEADER_LOW = Finding(
    header="X-Forwarded-Host",
    category=HeaderCategory.CACHING,
    severity=Severity.LOW,
    title="Low-risk cache poisoning via unkeyed header",
    description="An unkeyed request header is reflected in a low-risk context (body text or non-security header) of a cached response. The direct impact is limited but may indicate broader misconfiguration.",
    current_value=None,
    recommendation="Review whether the header needs to be processed by the application. If not, strip it at the proxy layer.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)

_WCP_LIVE_CACHE_POISONED = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.CRITICAL,
    title="Live cache poisoned during scan",
    description="A canary value injected during active probing was found in a clean (no cache buster) response. The live cache was inadvertently poisoned. This confirms the target is critically vulnerable and the poisoned entry will expire based on the cache TTL.",
    current_value=None,
    recommendation="Immediately purge the affected cache entry. Add the reflected header to the cache key or strip it at the proxy layer.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_ALT_SVC_POISONING = Finding(
    header="Alt-Svc",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="Alt-Svc cache poisoning via unkeyed header",
    description=(
        "An unkeyed request header is reflected into the cached Alt-Svc response "
        "header. This allows an attacker to poison the cache with an attacker-"
        "controlled HTTP/3 endpoint, pinning every subsequent victim browser to "
        "the attacker's QUIC server for the Alt-Svc TTL. The attack exploits the "
        "HTTP/2-to-HTTP/3 protocol upgrade to redirect clients transparently."
    ),
    current_value=None,
    recommendation=(
        "Add the reflected header to the cache key, or strip it at the CDN/proxy "
        "layer. Consider shortening Alt-Svc max-age for defense-in-depth."
    ),
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_ALT_SVC_CROSS_DOMAIN = Finding(
    header="Alt-Svc",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="Alt-Svc alt-authority on different registrable domain",
    description=(
        "The Alt-Svc header advertises an alternative service on a different "
        "registrable domain than the request target. A poisoned or malicious "
        "Alt-Svc value can pin browsers to an attacker-controlled HTTP/3 "
        "endpoint; a cross-domain alt-authority is a strong indicator of either "
        "misconfiguration or active exploitation."
    ),
    current_value=None,
    recommendation=(
        "Restrict Alt-Svc alt-authorities to the same registrable domain as the "
        "origin, or omit the host portion (port-only alt-authority) so the "
        "alternative defaults to the origin hostname."
    ),
    example_value='Alt-Svc: h3=":443"; ma=86400',
    reference_url="https://datatracker.ietf.org/doc/html/rfc7838#section-2.1",
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)

_WCP_ALT_SVC_PRIVATE_HOST = Finding(
    header="Alt-Svc",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="Alt-Svc advertises private or non-public alt-authority",
    description=(
        "The Alt-Svc alt-authority resolves to a private-network address "
        "(RFC1918, loopback) or a non-public TLD (.local, .internal, .invalid). "
        "This is almost always an internal-infrastructure leak into a public-"
        "facing response and indicates the Alt-Svc value is generated from an "
        "untrusted source or a stale internal config."
    ),
    current_value=None,
    recommendation=(
        "Strip Alt-Svc from responses served to the public internet when the "
        "alt-authority points to internal infrastructure. Configure the origin "
        "or CDN to override Alt-Svc at the edge."
    ),
    example_value='Alt-Svc: h3=":443"; ma=86400',
    reference_url="https://datatracker.ietf.org/doc/html/rfc7838#section-2.1",
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)

_WCP_ALT_SVC_EXCESSIVE_PERSISTENCE = Finding(
    header="Alt-Svc",
    category=HeaderCategory.CACHING,
    severity=Severity.LOW,
    title="Alt-Svc ma > 30 days combined with persist=1",
    description=(
        "The Alt-Svc header uses both a max-age greater than 30 days and "
        "persist=1, causing browsers to retain the alternative service mapping "
        "across network-configuration changes for an extended window. This "
        "amplifies the impact of any future Alt-Svc cache poisoning event by "
        "extending victim lock-in beyond the CDN cache TTL."
    ),
    current_value=None,
    recommendation=(
        "Reduce max-age to 86400 (24h) or less. Omit persist=1 unless the "
        "deployment specifically requires alternative services to survive "
        "network changes."
    ),
    example_value='Alt-Svc: h3=":443"; ma=86400',
    reference_url="https://datatracker.ietf.org/doc/html/rfc7838#section-3.1",
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)

_WCP_SET_COOKIE_POISONING = Finding(
    header="Set-Cookie",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="Set-Cookie cache poisoning via unkeyed header",
    description=(
        "An unkeyed request header is reflected into the cached Set-Cookie "
        "response header. A cached Set-Cookie from a poisoned response is "
        "delivered to every subsequent user, enabling session fixation or "
        "cookie injection attacks."
    ),
    current_value=None,
    recommendation=(
        "Responses that set cookies must be keyed by whatever influences the "
        "cookie value, or cached as private. Strip reflected headers at the "
        "CDN/proxy layer."
    ),
    example_value="Cache-Control: private, no-store",
    reference_url=_REF_URL,
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_CACHE_KEYING_UNDETERMINED = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.INFO,
    title="Cache keying could not be determined",
    description=(
        "The scanner could not conclusively determine whether the query string "
        "is part of the cache key. This occurs when the CDN does not expose "
        "cache status headers on the first request and does not provide a "
        "cache-key inspection mechanism. Active probing was skipped to avoid "
        "inadvertently poisoning the live cache."
    ),
    current_value=None,
    recommendation="Manually verify whether the query string is part of the cache key.",
    example_value="N/A",
    reference_url=_REF_URL,
)

_WCP_UNKEYED_HEADER_NO_REFLECT = Finding(
    header="X-Forwarded-Host",
    category=HeaderCategory.CACHING,
    severity=Severity.INFO,
    title="Unkeyed header detected (not reflected)",
    description="A request header is excluded from the cache key but its value is not currently reflected in the response. While not directly exploitable, changes to the application could introduce reflection in the future.",
    current_value=None,
    recommendation="Consider adding the header to the cache key or stripping it at the proxy layer as a defense-in-depth measure.",
    example_value="Vary: X-Forwarded-Host",
    reference_url=_REF_URL,
)

_WCP_PROBE_SKIPPED = Finding(
    header="Cache-Control",
    category=HeaderCategory.CACHING,
    severity=Severity.INFO,
    title="Active cache poisoning probing skipped",
    description="Active probing was skipped because no safe cache buster strategy could be established. The query string is not part of the cache key and no alternative buster was available via the Vary header. Note: a separate WCP_CACHE_KEYING_UNDETERMINED finding covers the distinct case where cache-key composition itself could not be confirmed.",
    current_value=None,
    recommendation="Manual testing recommended. Review cache key configuration.",
    example_value="N/A",
    reference_url=_REF_URL,
)

# -- Active findings: CPDoS --------------------------------------------------

_WCP_CPDOS_OVERSIZE = Finding(
    header="X-Oversized-Header",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="CPDoS via oversized header",
    description="An oversized request header causes the origin to return an error response (400/413/431) that the cache stores and serves to subsequent users. This is a Cache Poisoning Denial of Service (CPDoS) vulnerability.",
    current_value=None,
    recommendation="Configure the cache to not store error responses, or increase the origin's header size limit.",
    example_value="Cache-Control: no-store (on error responses)",
    reference_url="https://cpdos.org/",
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_CPDOS_MALFORMED = Finding(
    header="X-Malformed-Header",
    category=HeaderCategory.CACHING,
    severity=Severity.HIGH,
    title="CPDoS via malformed header",
    description="A malformed request header causes the origin to return an error response that the cache stores and serves to subsequent users. This is a Cache Poisoning Denial of Service (CPDoS) vulnerability.",
    current_value=None,
    recommendation="Configure the cache to not store error responses. Review origin error handling.",
    example_value="Cache-Control: no-store (on error responses)",
    reference_url="https://cpdos.org/",
    compliance_mappings=[_OWASP_A05, _PCI_6_2],
    cve_correlations=[_CWE_444],
)

_WCP_CPDOS_METHOD_OVERRIDE = Finding(
    header="X-HTTP-Method-Override",
    category=HeaderCategory.CACHING,
    severity=Severity.MEDIUM,
    title="CPDoS via method override",
    description="The X-HTTP-Method-Override header is unkeyed and causes the origin to process a GET request as a different method (e.g., POST). The resulting response is cached and served to subsequent GET requests, potentially exposing error pages or different content.",
    current_value=None,
    recommendation="Strip method override headers at the proxy layer, or add them to the cache key.",
    example_value="Vary: X-HTTP-Method-Override",
    reference_url="https://cpdos.org/",
    compliance_mappings=[_OWASP_A05],
    cve_correlations=[_CWE_444],
)


# -- Registry -----------------------------------------------------------------

ALL_CACHE_FINDINGS: dict[str, Finding] = {
    # Passive
    "WCP_NOT_CACHED": _WCP_NOT_CACHED,
    "WCP_CDN_DETECTED": _WCP_CDN_DETECTED,
    "WCP_PERMISSIVE_CACHE_CONTROL": _WCP_PERMISSIVE_CACHE_CONTROL,
    "WCP_NO_VARY_ORIGIN": _WCP_NO_VARY_ORIGIN,
    "WCP_CACHE_PUBLIC_SENSITIVE": _WCP_CACHE_PUBLIC_SENSITIVE,
    "WCP_NO_CACHE_KEY_QS": _WCP_NO_CACHE_KEY_QS,
    "WCP_CACHE_KEYING_UNDETERMINED": _WCP_CACHE_KEYING_UNDETERMINED,
    # Active - reflection
    "WCP_UNKEYED_HEADER_CRITICAL": _WCP_UNKEYED_HEADER_CRITICAL,
    "WCP_UNKEYED_HEADER_HIGH": _WCP_UNKEYED_HEADER_HIGH,
    "WCP_UNKEYED_HEADER_MEDIUM": _WCP_UNKEYED_HEADER_MEDIUM,
    "WCP_UNKEYED_HEADER_LOW": _WCP_UNKEYED_HEADER_LOW,
    "WCP_LIVE_CACHE_POISONED": _WCP_LIVE_CACHE_POISONED,
    "WCP_UNKEYED_HEADER_NO_REFLECT": _WCP_UNKEYED_HEADER_NO_REFLECT,
    "WCP_PROBE_SKIPPED": _WCP_PROBE_SKIPPED,
    "WCP_ALT_SVC_POISONING": _WCP_ALT_SVC_POISONING,
    "WCP_ALT_SVC_CROSS_DOMAIN": _WCP_ALT_SVC_CROSS_DOMAIN,
    "WCP_ALT_SVC_PRIVATE_HOST": _WCP_ALT_SVC_PRIVATE_HOST,
    "WCP_ALT_SVC_EXCESSIVE_PERSISTENCE": _WCP_ALT_SVC_EXCESSIVE_PERSISTENCE,
    "WCP_SET_COOKIE_POISONING": _WCP_SET_COOKIE_POISONING,
    # Active - CPDoS
    "WCP_CPDOS_OVERSIZE": _WCP_CPDOS_OVERSIZE,
    "WCP_CPDOS_MALFORMED": _WCP_CPDOS_MALFORMED,
    "WCP_CPDOS_METHOD_OVERRIDE": _WCP_CPDOS_METHOD_OVERRIDE,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    template = ALL_CACHE_FINDINGS.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)
