"""FetchMetadataAuditor — orchestrates the four-probe canary-extended sequence.

Sync entry point `audit()` runs `_audit_async()` via `asyncio.run`. Mirrors
the established pattern in corsair.cors.auditor and corsair.cache.auditor.
"""

import asyncio
import logging
from typing import List, Mapping

import httpx

from ..cache.oracle import fingerprint_cdn
from ..models import Finding
from .findings import (
    FMContext,
    build_enforced_finding,
    build_inconclusive_finding,
    build_not_enforced_finding,
)
from .probe import (
    ADVERSARIAL_PROBE_HEADERS,
    CANARY_PROBE_HEADERS,
    EnforcementResult,
    SAFE_PROBE_HEADERS,
    _body_hash,
    classify_enforcement,
)

logger = logging.getLogger(__name__)


_CSRF_COOKIE_NAMES = frozenset({
    "csrftoken",
    "xsrf-token",
    "_csrf",
    "__requestverificationtoken",
    "csrf",
})

_SESSION_COOKIE_NAMES = ("session", "sessionid", "sid", "auth", "token", "jwt")


class FetchMetadataAuditor:
    def __init__(self, timeout: float = 10.0, active: bool = True):
        self.timeout = timeout
        self.active = active

    def audit(self, url: str, baseline_headers: Mapping[str, str]) -> List[Finding]:
        if not self.active:
            return []
        try:
            return asyncio.run(self._audit_async(url, baseline_headers))
        except Exception as e:
            logger.error(f"FetchMetadata audit failed for {url}: {e}")
            return []

    async def _audit_async(
        self, url: str, baseline_headers: Mapping[str, str]
    ) -> List[Finding]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=True,
        ) as client:
            try:
                baseline_resp, safe_resp, adv_resp, canary_resp = await asyncio.gather(
                    client.get(url),
                    client.get(url, headers=dict(SAFE_PROBE_HEADERS)),
                    client.get(url, headers=dict(ADVERSARIAL_PROBE_HEADERS)),
                    client.get(url, headers=dict(CANARY_PROBE_HEADERS)),
                )
            except httpx.RequestError as e:
                logger.warning(f"FM probe network error on {url}: {e}")
                return [build_inconclusive_finding("Network error during probe sequence")]

        baseline_body = _body_hash(baseline_resp.content)
        adversarial_body = _body_hash(adv_resp.content)

        result = classify_enforcement(
            baseline_status=baseline_resp.status_code,
            safe_status=safe_resp.status_code,
            adversarial_status=adv_resp.status_code,
            canary_status=canary_resp.status_code,
            baseline_body_hash=baseline_body,
            adversarial_body_hash=adversarial_body,
        )

        ctx = self._infer_context(baseline_headers)

        if result == EnforcementResult.ENFORCED:
            return [build_enforced_finding()]

        if result == EnforcementResult.SOFT_ENFORCED:
            return [build_not_enforced_finding(ctx, soft=True)]

        if result == EnforcementResult.NOT_ENFORCED:
            return [build_not_enforced_finding(ctx, soft=False)]

        # INCONCLUSIVE
        reason = self._inconclusive_reason(
            baseline_resp.status_code,
            safe_resp.status_code,
            adv_resp.status_code,
        )
        return [build_inconclusive_finding(reason)]

    @staticmethod
    def _infer_context(headers: Mapping[str, str]) -> FMContext:
        cdn = fingerprint_cdn(dict(headers))
        cookies = _iter_set_cookies(headers)

        has_strict = any(
            _is_session_cookie(c) and "samesite=strict" in c.lower() for c in cookies
        )
        has_lax = any(
            _is_session_cookie(c) and "samesite=lax" in c.lower() for c in cookies
        )
        has_csrf = any(_is_csrf_cookie(c) for c in cookies)

        return FMContext(
            has_samesite_strict=has_strict,
            has_samesite_lax=has_lax,
            has_csrf_token=has_csrf,
            cdn_detected=cdn is not None,
        )

    @staticmethod
    def _inconclusive_reason(baseline_status: int, safe_status: int, adv_status: int) -> str:
        if safe_status in {400, 403, 405, 451}:
            return "Safe-probe rejected — server appears to blanket-reject Sec-Fetch headers"
        if baseline_status >= 500 or baseline_status == 401:
            return f"Baseline target returned {baseline_status} — cannot probe meaningfully"
        if adv_status in {301, 302, 303, 307, 308}:
            return f"Adversarial probe redirected ({adv_status}); likely auth, not enforcement"
        return f"Unclassified probe pattern (baseline={baseline_status}, adversarial={adv_status})"


def _iter_set_cookies(headers: Mapping[str, str]) -> list[str]:
    """Extract individual Set-Cookie strings from a header mapping.

    Comma-splits a single Set-Cookie value containing multiple cookies (the
    httpx response.headers may collapse duplicates). The split is naive but
    sufficient for SameSite / cookie-name detection.
    """
    cookies: list[str] = []
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        # Cookie attributes contain commas only inside `Expires=...` dates,
        # but those use `, ` after the day name. We split on `, ` (comma+space)
        # only when the next chunk starts with a token=value pattern.
        parts = _split_multicookie(value)
        cookies.extend(parts)
    return cookies


def _split_multicookie(raw: str) -> list[str]:
    """Split a comma-joined multi-cookie Set-Cookie value into individual cookies.
    Robust against `Expires=Wed, 09 Jun 2027 ...` by requiring `, name=` shape."""
    out: list[str] = []
    buf: list[str] = []
    pending = raw
    while pending:
        idx = pending.find(", ")
        if idx == -1:
            buf.append(pending)
            break
        head, tail = pending[:idx], pending[idx + 2 :]
        # If the tail begins with a `name=value` pattern (not `09 Jun 2027`),
        # this is a cookie boundary.
        eq = tail.find("=")
        sp = tail.find(" ")
        if eq != -1 and (sp == -1 or eq < sp):
            buf.append(head)
            out.append("".join(buf).strip())
            buf = []
            pending = tail
        else:
            buf.append(head + ", ")
            pending = tail
    if buf:
        out.append("".join(buf).strip())
    return [c for c in out if c]


def _is_session_cookie(cookie: str) -> bool:
    name = cookie.split("=", 1)[0].strip().lower()
    return any(s in name for s in _SESSION_COOKIE_NAMES)


def _is_csrf_cookie(cookie: str) -> bool:
    name = cookie.split("=", 1)[0].strip().lower()
    return name in _CSRF_COOKIE_NAMES
