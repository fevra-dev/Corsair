"""
Fingerprinting Engine.

Detects technologies from HTTP response headers using
pattern matching against a database of 1,200+ signatures.

Supports detection of:
- Web servers (Apache, Nginx, IIS, etc.)
- CDNs (Cloudflare, AWS CloudFront, Akamai, Fastly)
- WAFs (Cloudflare WAF, AWS WAF, Imperva, F5)
- Frameworks (Express, Django, Next.js, WordPress)
- Load balancers and caches
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from ..models import FingerprintResult
from ..utils.logger import get_logger
from .signatures import SIGNATURES, get_all_signatures

logger = get_logger(__name__)


class FingerprintEngine:
    """
    Technology fingerprinting engine.
    
    Analyzes HTTP response headers and cookies to detect
    underlying technologies, servers, CDNs, and frameworks.
    
    Usage:
        engine = FingerprintEngine()
        results = engine.detect(headers, cookies, status_code)
        
        for result in results:
            print(f"{result.category}: {result.name} v{result.version}")
    """
    
    def __init__(self, signatures: Dict = None):
        """
        Initialize the fingerprint engine.
        
        Args:
            signatures: Optional custom signature database.
                       Uses default SIGNATURES if not provided.
        """
        self.signatures = signatures or get_all_signatures()
        self._compiled_patterns: Dict[str, Dict] = {}
        self._compile_patterns()
        
        logger.info(f"[Fingerprint] Engine initialized with {self._count_patterns()} patterns")
    
    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for category, techs in self.signatures.items():
            self._compiled_patterns[category] = {}
            for tech_name, tech_config in techs.items():
                compiled = []
                for pattern in tech_config.get("patterns", []):
                    try:
                        regex = re.compile(pattern.get("regex", ""), re.IGNORECASE)
                        compiled.append({
                            **pattern,
                            "compiled_regex": regex
                        })
                    except re.error as e:
                        logger.warning(f"[Fingerprint] Invalid regex for {tech_name}: {e}")
                
                self._compiled_patterns[category][tech_name] = {
                    "patterns": compiled,
                    "confidence_base": tech_config.get("confidence_base", 0.5)
                }
    
    def _count_patterns(self) -> int:
        """Count total compiled patterns."""
        total = 0
        for category in self._compiled_patterns.values():
            for tech in category.values():
                total += len(tech.get("patterns", []))
        return total
    
    def detect(
        self,
        headers: Dict[str, str],
        cookies: Optional[Dict[str, str]] = None,
        status_code: int = 200
    ) -> List[FingerprintResult]:
        """
        Detect technologies from HTTP response.
        
        Args:
            headers: Response headers (case-insensitive)
            cookies: Parsed cookies (optional)
            status_code: HTTP response status code
            
        Returns:
            List of FingerprintResult objects sorted by confidence
        """
        results = []
        cookies = cookies or {}
        
        # Normalize headers to lowercase keys
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        logger.debug(f"[Fingerprint] Analyzing {len(headers)} headers, {len(cookies)} cookies")
        
        # Check each category
        for category, techs in self._compiled_patterns.items():
            for tech_name, tech_config in techs.items():
                result = self._check_technology(
                    category=category,
                    tech_name=tech_name,
                    patterns=tech_config["patterns"],
                    confidence_base=tech_config["confidence_base"],
                    headers=headers_lower,
                    cookies=cookies,
                    status_code=status_code
                )
                
                if result:
                    results.append(result)
        
        # Sort by confidence descending
        results.sort(key=lambda x: x.confidence, reverse=True)
        
        # Remove duplicates - keep highest confidence per technology
        seen_techs: Set[str] = set()
        unique_results = []
        for r in results:
            key = f"{r.category}:{r.name}"
            if key not in seen_techs:
                seen_techs.add(key)
                unique_results.append(r)
        
        logger.info(f"[Fingerprint] Detected {len(unique_results)} technologies")
        for r in unique_results[:5]:  # Log top 5
            logger.debug(f"[Fingerprint] {r.category}: {r.name} v{r.version} ({r.confidence:.0%})")
        
        return unique_results
    
    def _check_technology(
        self,
        category: str,
        tech_name: str,
        patterns: List[Dict],
        confidence_base: float,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        status_code: int
    ) -> Optional[FingerprintResult]:
        """
        Check if a specific technology is detected.
        
        Args:
            category: Technology category
            tech_name: Technology name
            patterns: List of pattern configs with compiled regexes
            confidence_base: Base confidence score
            headers: Lowercase response headers
            cookies: Response cookies
            status_code: HTTP status code
            
        Returns:
            FingerprintResult if detected, None otherwise
        """
        matched_patterns = []
        version = None
        confidence = 0.0
        
        for pattern in patterns:
            # Check status code requirement
            required_status = pattern.get("status_code")
            if required_status and status_code != required_status:
                continue
            
            regex = pattern.get("compiled_regex")
            if not regex:
                continue
            
            # Check header pattern
            if "header" in pattern:
                header_name = pattern["header"].lower()
                header_value = headers.get(header_name)
                
                if header_value:
                    match = regex.search(header_value)
                    if match:
                        matched_patterns.append(pattern["header"])
                        confidence += 0.25
                        
                        # Extract version if available
                        version_group = pattern.get("version_group")
                        if version_group and match.groups():
                            try:
                                version = match.group(version_group)
                            except IndexError:
                                pass
            
            # Check cookie pattern
            if "cookie" in pattern:
                cookie_prefix = pattern["cookie"]
                for cookie_name in cookies.keys():
                    if cookie_name.startswith(cookie_prefix):
                        matched_patterns.append(f"cookie:{cookie_name}")
                        confidence += 0.2
                        break
        
        # Return result if any patterns matched
        if matched_patterns:
            # Cap confidence at base confidence
            final_confidence = min(confidence_base, confidence)
            
            return FingerprintResult(
                category=category,
                name=tech_name,
                version=version,
                confidence=round(final_confidence, 2),
                evidence=", ".join(matched_patterns[:3])  # Limit evidence length
            )
        
        return None
    
    def detect_from_raw(self, raw_headers: str) -> List[FingerprintResult]:
        """
        Detect technologies from raw header string.
        
        Args:
            raw_headers: Raw HTTP headers as string
            
        Returns:
            List of FingerprintResult objects
        """
        headers = {}
        for line in raw_headers.strip().split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        
        return self.detect(headers)
    
    def get_info_disclosure_findings(
        self,
        results: List[FingerprintResult]
    ) -> List[Tuple[str, str, str]]:
        """
        Get information disclosure findings from fingerprint results.
        
        Some technologies should not be exposed:
        - Server version numbers
        - Framework versions
        - Development indicators
        
        Args:
            results: Fingerprint detection results
            
        Returns:
            List of (severity, title, description) tuples
        """
        findings = []
        
        for result in results:
            # Version disclosure
            if result.version:
                if result.category in ("server", "framework"):
                    findings.append((
                        "LOW",
                        f"{result.name} version disclosed",
                        f"The {result.name} version ({result.version}) is exposed in HTTP headers. "
                        f"Evidence: {result.evidence}"
                    ))
            
            # Framework disclosure via X-Powered-By
            if result.category == "framework" and "X-Powered-By" in result.evidence:
                findings.append((
                    "INFO",
                    f"{result.name} framework exposed",
                    f"The {result.name} framework is disclosed via X-Powered-By header. "
                    "Consider removing this header in production."
                ))
        
        return findings


def create_engine() -> FingerprintEngine:
    """Factory function to create a FingerprintEngine instance."""
    return FingerprintEngine()
