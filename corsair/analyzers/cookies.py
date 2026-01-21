"""
Cookie security flags analyzer.

Analyzes Set-Cookie headers for security flags: Secure, HttpOnly, SameSite.
"""

from typing import List
import logging

from .base import BaseAnalyzer
from ..models import Finding, Severity, HeaderCategory

logger = logging.getLogger(__name__)


class CookieAnalyzer(BaseAnalyzer):
    """Analyzer for Set-Cookie headers."""

    HEADER_NAME = "Set-Cookie"
    CATEGORY = HeaderCategory.COOKIES

    MDN_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"

    def analyze(self) -> List[Finding]:
        """Analyze Set-Cookie headers."""
        findings = []

        # Get all Set-Cookie headers
        cookies = []
        for key, value in self.headers.items():
            if key.lower() == "set-cookie":
                cookies.append(value)

        if not cookies:
            logger.info("[Cookies] No Set-Cookie headers")
            # Not a finding - page might not set cookies
            return findings

        logger.info(f"[Cookies] Found {len(cookies)} Set-Cookie header(s)")

        for cookie in cookies:
            cookie_findings = self._analyze_cookie(cookie)
            findings.extend(cookie_findings)

        return findings

    def _analyze_cookie(self, cookie: str) -> List[Finding]:
        """Analyze a single cookie for security issues."""
        findings = []

        # Extract cookie name
        parts = cookie.split(";")
        name_value = parts[0].strip()
        cookie_name = name_value.split("=")[0] if "=" in name_value else "unknown"

        cookie_lower = cookie.lower()

        # Check for Secure flag (HTTPS only)
        has_secure = "secure" in cookie_lower

        # Check for HttpOnly flag (no JavaScript access)
        has_httponly = "httponly" in cookie_lower

        # Check for SameSite attribute
        has_samesite = "samesite" in cookie_lower
        samesite_value = None
        if has_samesite:
            for part in parts:
                if "samesite" in part.lower():
                    if "=" in part:
                        samesite_value = part.split("=")[1].strip().lower()

        is_https = self.url.lower().startswith("https://")

        # Missing Secure on HTTPS site
        if is_https and not has_secure:
            findings.append(
                self.create_finding(
                    severity=Severity.HIGH,
                    title=f"Cookie '{cookie_name}' Missing Secure Flag",
                    description=(
                        "The Secure flag is not set. The cookie can be transmitted "
                        "over unencrypted HTTP, potentially exposing session data."
                    ),
                    current_value=cookie,
                    recommendation="Add the Secure flag to all cookies on HTTPS sites.",
                    example_value=f"{cookie_name}=value; Secure; HttpOnly; SameSite=Strict",
                    reference_url=self.MDN_URL,
                )
            )

        # Missing HttpOnly
        if not has_httponly:
            # Check if it's likely a session/auth cookie
            sensitive_names = ["session", "token", "auth", "sid", "jwt", "csrf"]
            is_sensitive = any(s in cookie_name.lower() for s in sensitive_names)

            if is_sensitive:
                findings.append(
                    self.create_finding(
                        severity=Severity.HIGH,
                        title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                        description=(
                            "The HttpOnly flag is not set on what appears to be a "
                            "sensitive cookie. JavaScript can access this cookie, "
                            "making it vulnerable to XSS attacks."
                        ),
                        current_value=cookie,
                        recommendation="Add HttpOnly flag to prevent JavaScript access.",
                        example_value=f"{cookie_name}=value; Secure; HttpOnly; SameSite=Strict",
                        reference_url=self.MDN_URL,
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        severity=Severity.MEDIUM,
                        title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                        description=(
                            "The HttpOnly flag is not set. JavaScript can access this cookie."
                        ),
                        current_value=cookie,
                        recommendation="Consider adding HttpOnly if not needed by JavaScript.",
                        example_value=f"{cookie_name}=value; Secure; HttpOnly",
                        reference_url=self.MDN_URL,
                    )
                )

        # Missing or weak SameSite
        if not has_samesite:
            findings.append(
                self.create_finding(
                    severity=Severity.MEDIUM,
                    title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                    description=(
                        "The SameSite attribute is not set. Modern browsers default to 'Lax', "
                        "but explicitly setting it ensures consistent behavior and provides "
                        "CSRF protection."
                    ),
                    current_value=cookie,
                    recommendation="Add SameSite=Strict or SameSite=Lax.",
                    example_value=f"{cookie_name}=value; SameSite=Strict",
                    reference_url=self.MDN_URL,
                )
            )
        elif samesite_value == "none" and not has_secure:
            findings.append(
                self.create_finding(
                    severity=Severity.HIGH,
                    title=f"Cookie '{cookie_name}' SameSite=None Without Secure",
                    description=(
                        "SameSite=None requires the Secure flag. "
                        "Without it, modern browsers will reject the cookie."
                    ),
                    current_value=cookie,
                    recommendation="Add Secure flag when using SameSite=None.",
                    example_value=f"{cookie_name}=value; Secure; SameSite=None",
                    reference_url=self.MDN_URL,
                )
            )

        return findings
