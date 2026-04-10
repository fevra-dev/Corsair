"""
TLS finding definitions.

All TLS-related findings that the TLSAuditor can produce.
Each finding uses the existing Finding dataclass with HeaderCategory.TRANSPORT.
"""

import copy
from typing import Optional

from ..models import (
    Finding,
    Severity,
    HeaderCategory,
    CVECorrelation,
    ComplianceMapping,
)


def _compliance(framework: str, req_id: str, req_name: str, status: str = "FAIL"):
    return ComplianceMapping(
        framework=framework,
        requirement_id=req_id,
        requirement_name=req_name,
        status=status,
    )


def _cve(cve_id: str, cvss: float, desc: str, kev: bool = False):
    return CVECorrelation(
        cve_id=cve_id,
        cvss_score=cvss,
        description=desc,
        in_cisa_kev=kev,
    )


# Standard compliance mappings reused across TLS findings
_OWASP_A02 = _compliance("OWASP_TOP_10_2025", "A02", "Security Misconfiguration")
_PCI_TLS = _compliance("PCI_DSS_4_0", "4.2.1", "Strong cryptography for transmission")
_NIST_TLS = _compliance("NIST_SP_800_52R2", "3.1", "TLS version requirements")


# ── Protocol Findings ────────────────────────────────────────────────────────

_TLS_MISSING = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="No TLS — Target Uses HTTP Only",
    description=(
        "The target does not use HTTPS. All data is transmitted in cleartext, "
        "allowing interception, modification, and credential theft."
    ),
    current_value="http://",
    recommendation="Enable TLS on the server and redirect all HTTP traffic to HTTPS.",
    example_value="https://example.com",
    reference_url="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
    compliance_mappings=[_OWASP_A02, _PCI_TLS, _NIST_TLS],
)

_TLS_CONNECT_FAILED = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.MEDIUM,
    title="TLS Connection Failed",
    description="Could not establish a TLS connection to the target. The server may be down, behind a firewall, or misconfigured.",
    current_value=None,
    recommendation="Verify the server is running and TLS is properly configured.",
    example_value="N/A",
    reference_url="https://wiki.mozilla.org/Security/Server_Side_TLS",
)

_DEPRECATED_PROTOCOL_SSL2 = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="SSLv2 Enabled (DROWN)",
    description=(
        "The server supports SSLv2, which is fundamentally broken. "
        "Vulnerable to the DROWN attack, allowing decryption of TLS traffic "
        "using SSLv2 as an oracle."
    ),
    current_value="SSLv2 supported",
    recommendation="Disable SSLv2 immediately. Minimum supported protocol should be TLS 1.2.",
    example_value="TLS 1.2, TLS 1.3",
    reference_url="https://drownattack.com/",
    cve_correlations=[_cve("CVE-2016-0800", 5.9, "DROWN: SSLv2 cross-protocol attack", kev=False)],
    compliance_mappings=[_OWASP_A02, _PCI_TLS, _NIST_TLS],
)

_DEPRECATED_PROTOCOL_SSL3 = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="SSLv3 Enabled (POODLE)",
    description=(
        "The server supports SSLv3, which is vulnerable to the POODLE attack. "
        "An attacker can exploit CBC padding oracle to decrypt HTTPS traffic."
    ),
    current_value="SSLv3 supported",
    recommendation="Disable SSLv3 immediately. Minimum supported protocol should be TLS 1.2.",
    example_value="TLS 1.2, TLS 1.3",
    reference_url="https://www.openssl.org/~bodo/ssl-poodle.pdf",
    cve_correlations=[_cve("CVE-2014-3566", 3.4, "POODLE: SSLv3 CBC padding oracle", kev=False)],
    compliance_mappings=[_OWASP_A02, _PCI_TLS, _NIST_TLS],
)

_DEPRECATED_PROTOCOL_TLS10 = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.HIGH,
    title="TLS 1.0 Enabled (BEAST)",
    description=(
        "The server supports TLS 1.0, which is deprecated (RFC 8996). "
        "Vulnerable to the BEAST attack via predictable CBC initialization vectors."
    ),
    current_value="TLS 1.0 supported",
    recommendation="Disable TLS 1.0. Minimum supported protocol should be TLS 1.2.",
    example_value="TLS 1.2, TLS 1.3",
    reference_url="https://datatracker.ietf.org/doc/html/rfc8996",
    cve_correlations=[_cve("CVE-2011-3389", 4.3, "BEAST: TLS 1.0 CBC predictable IV")],
    compliance_mappings=[_OWASP_A02, _PCI_TLS, _NIST_TLS],
)

_DEPRECATED_PROTOCOL_TLS11 = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.HIGH,
    title="TLS 1.1 Enabled",
    description=(
        "The server supports TLS 1.1, which is deprecated (RFC 8996). "
        "All major browsers have removed TLS 1.1 support."
    ),
    current_value="TLS 1.1 supported",
    recommendation="Disable TLS 1.1. Minimum supported protocol should be TLS 1.2.",
    example_value="TLS 1.2, TLS 1.3",
    reference_url="https://datatracker.ietf.org/doc/html/rfc8996",
    compliance_mappings=[_OWASP_A02, _PCI_TLS, _NIST_TLS],
)

_TLS13_NOT_SUPPORTED = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.MEDIUM,
    title="TLS 1.3 Not Supported",
    description=(
        "The server does not support TLS 1.3. As of 2025, Qualys SSL Labs "
        "caps the grade at A- when TLS 1.3 is absent."
    ),
    current_value="TLS 1.3 not supported",
    recommendation="Enable TLS 1.3 in server configuration.",
    example_value="ssl_protocols TLSv1.2 TLSv1.3;",
    reference_url="https://datatracker.ietf.org/doc/html/rfc8446",
    compliance_mappings=[_OWASP_A02, _NIST_TLS],
)

# ── Cipher Findings ──────────────────────────────────────────────────────────

_WEAK_CIPHER_RC4 = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="RC4 Cipher Suite Offered",
    description="The server offers RC4 cipher suites, which are prohibited by RFC 7465 due to known biases in the keystream.",
    current_value="RC4 cipher suite accepted",
    recommendation="Remove all RC4 cipher suites from server configuration.",
    example_value="TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256",
    reference_url="https://datatracker.ietf.org/doc/html/rfc7465",
    cve_correlations=[_cve("CWE-327", 5.9, "Use of broken cryptographic algorithm")],
    compliance_mappings=[_OWASP_A02, _PCI_TLS],
)

_WEAK_CIPHER_3DES = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.HIGH,
    title="3DES Cipher Suite Offered (Sweet32)",
    description="The server offers 3DES cipher suites, which are vulnerable to the Sweet32 birthday attack on 64-bit block ciphers.",
    current_value="3DES cipher suite accepted",
    recommendation="Remove 3DES cipher suites. Use AES-GCM or ChaCha20-Poly1305.",
    example_value="TLS_AES_256_GCM_SHA384",
    reference_url="https://sweet32.info/",
    cve_correlations=[_cve("CVE-2016-2183", 5.3, "Sweet32: birthday attack on 64-bit block ciphers")],
    compliance_mappings=[_OWASP_A02, _PCI_TLS],
)

_WEAK_CIPHER_NULL = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="NULL Cipher Suite Offered",
    description="The server offers NULL cipher suites, which provide no encryption. Traffic is transmitted in cleartext despite the TLS wrapper.",
    current_value="NULL cipher suite accepted",
    recommendation="Remove all NULL cipher suites from server configuration.",
    example_value="TLS_AES_256_GCM_SHA384",
    reference_url="https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml",
    compliance_mappings=[_OWASP_A02, _PCI_TLS, _NIST_TLS],
)

_WEAK_CIPHER_EXPORT = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="EXPORT-Grade Cipher Suite Offered (LOGJAM)",
    description="The server offers EXPORT-grade cipher suites with intentionally weakened key sizes (40-56 bit). Vulnerable to the LOGJAM attack.",
    current_value="EXPORT cipher suite accepted",
    recommendation="Remove all EXPORT cipher suites from server configuration.",
    example_value="TLS_AES_256_GCM_SHA384",
    reference_url="https://weakdh.org/",
    cve_correlations=[_cve("CVE-2015-4000", 3.7, "LOGJAM: DHE export downgrade attack")],
    compliance_mappings=[_OWASP_A02, _PCI_TLS, _NIST_TLS],
)

_NO_FORWARD_SECRECY = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.HIGH,
    title="No Forward Secrecy",
    description="The server does not offer any cipher suites with forward secrecy (ECDHE/DHE) in TLS 1.2. If the server's private key is compromised, all past traffic can be decrypted.",
    current_value="No ECDHE/DHE suites",
    recommendation="Enable ECDHE cipher suites. Prefer TLS 1.3 which mandates forward secrecy.",
    example_value="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    reference_url="https://csrc.nist.gov/pubs/sp/800/52/r2/final",
    compliance_mappings=[_OWASP_A02, _PCI_TLS, _NIST_TLS],
)

_WEAK_DH_PARAMS = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.HIGH,
    title="Weak Diffie-Hellman Parameters",
    description="The server uses DH parameters smaller than 2048 bits, which are vulnerable to precomputation attacks.",
    current_value=None,
    recommendation="Use DH parameters of at least 2048 bits, or prefer ECDHE.",
    example_value="DH 2048-bit or ECDHE with P-256/X25519",
    reference_url="https://weakdh.org/",
    cve_correlations=[_cve("CVE-2015-4000", 3.7, "LOGJAM: weak DH parameters")],
    compliance_mappings=[_OWASP_A02, _NIST_TLS],
)

# ── Certificate Findings ─────────────────────────────────────────────────────

_CERT_EXPIRED = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="Certificate Expired",
    description="The server's TLS certificate has expired. Browsers will show security warnings and may block access entirely.",
    current_value=None,
    recommendation="Renew the certificate immediately. Consider automated renewal via ACME/Let's Encrypt.",
    example_value="Valid certificate with 90+ days remaining",
    reference_url="https://letsencrypt.org/docs/",
    compliance_mappings=[_OWASP_A02, _PCI_TLS],
)

_CERT_EXPIRING_SOON = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.MEDIUM,
    title="Certificate Expiring Soon",
    description="The server's TLS certificate expires within 30 days.",
    current_value=None,
    recommendation="Renew the certificate before it expires. Set up automated renewal.",
    example_value="Valid certificate with 90+ days remaining",
    reference_url="https://letsencrypt.org/docs/",
    compliance_mappings=[_OWASP_A02],
)

_CERT_SELF_SIGNED = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.HIGH,
    title="Self-Signed Certificate",
    description="The server uses a self-signed certificate that is not trusted by any public certificate authority. Browsers will reject this certificate.",
    current_value="Self-signed / untrusted CA",
    recommendation="Use a certificate from a trusted CA. Let's Encrypt provides free certificates.",
    example_value="Certificate signed by a trusted CA",
    reference_url="https://letsencrypt.org/",
    compliance_mappings=[_OWASP_A02, _PCI_TLS],
)

_CERT_HOSTNAME_MISMATCH = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="Certificate Hostname Mismatch",
    description="The certificate's Common Name (CN) and Subject Alternative Names (SANs) do not match the requested hostname. Browsers will reject this connection.",
    current_value=None,
    recommendation="Reissue the certificate with the correct hostname in the SAN field.",
    example_value="Certificate SAN includes target hostname",
    reference_url="https://cabforum.org/baseline-requirements/",
    compliance_mappings=[_OWASP_A02, _PCI_TLS],
)

_CERT_WEAK_SIGNATURE = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.HIGH,
    title="Weak Certificate Signature Algorithm",
    description="The certificate or its chain uses SHA-1 or MD5 for signatures, which are vulnerable to collision attacks.",
    current_value=None,
    recommendation="Reissue the certificate with SHA-256 or stronger signature algorithm.",
    example_value="SHA-256 with RSA / ECDSA",
    reference_url="https://cabforum.org/baseline-requirements/",
    cve_correlations=[_cve("CWE-328", 5.9, "Use of weak hash")],
    compliance_mappings=[_OWASP_A02, _PCI_TLS],
)

_CERT_SHORT_KEY = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.HIGH,
    title="Certificate Key Too Short",
    description="The certificate uses an RSA key smaller than 2048 bits, which does not meet current security standards.",
    current_value=None,
    recommendation="Reissue the certificate with at least a 2048-bit RSA key or 256-bit ECC key.",
    example_value="RSA 2048-bit or ECC P-256",
    reference_url="https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
    compliance_mappings=[_OWASP_A02, _PCI_TLS, _NIST_TLS],
)

_NO_OCSP_STAPLING = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.LOW,
    title="OCSP Stapling Not Enabled",
    description="The server does not staple OCSP responses. Clients must contact the CA's OCSP responder separately, adding latency and a privacy leak.",
    current_value="OCSP stapling disabled",
    recommendation="Enable OCSP stapling in server configuration.",
    example_value="ssl_stapling on; (nginx)",
    reference_url="https://wiki.mozilla.org/Security/Server_Side_TLS#OCSP_Stapling",
    compliance_mappings=[_OWASP_A02],
)

# ── Vulnerability Findings ───────────────────────────────────────────────────

_HEARTBLEED = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="Vulnerable to Heartbleed",
    description="The server is vulnerable to the Heartbleed bug (CVE-2014-0160), allowing attackers to read server memory including private keys, session tokens, and passwords.",
    current_value="Heartbleed vulnerable",
    recommendation="Upgrade OpenSSL immediately to a patched version (>= 1.0.1g). Revoke and reissue all certificates. Rotate all credentials.",
    example_value="OpenSSL >= 1.0.1g",
    reference_url="https://heartbleed.com/",
    cve_correlations=[_cve("CVE-2014-0160", 7.5, "Heartbleed: OpenSSL heartbeat buffer overread", kev=True)],
    compliance_mappings=[_OWASP_A02, _PCI_TLS, _NIST_TLS],
)

_ROBOT = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="Vulnerable to ROBOT Attack",
    description="The server is vulnerable to the ROBOT attack (Return Of Bleichenbacher's Oracle Threat), allowing decryption of RSA key exchanges.",
    current_value="ROBOT vulnerable",
    recommendation="Disable RSA key exchange cipher suites. Use only ECDHE-based key exchange.",
    example_value="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    reference_url="https://robotattack.org/",
    cve_correlations=[_cve("CVE-2017-13099", 5.9, "ROBOT: Bleichenbacher RSA padding oracle")],
    compliance_mappings=[_OWASP_A02, _PCI_TLS],
)

_OPENSSL_CCS_INJECTION = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.CRITICAL,
    title="OpenSSL CCS Injection Vulnerability",
    description="The server is vulnerable to the CCS Injection attack (CVE-2014-0224), allowing an attacker to intercept and decrypt traffic via a man-in-the-middle attack.",
    current_value="CCS injection vulnerable",
    recommendation="Upgrade OpenSSL to a patched version.",
    example_value="OpenSSL >= 1.0.1h",
    reference_url="https://www.openssl.org/news/secadv/20140605.txt",
    cve_correlations=[_cve("CVE-2014-0224", 6.8, "OpenSSL CCS Injection")],
    compliance_mappings=[_OWASP_A02, _PCI_TLS],
)

_TLS_COMPRESSION = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.HIGH,
    title="TLS Compression Enabled (CRIME)",
    description="The server has TLS-level compression enabled, making it vulnerable to the CRIME attack which can extract secrets from compressed encrypted traffic.",
    current_value="DEFLATE compression enabled",
    recommendation="Disable TLS compression in server configuration.",
    example_value="ssl_comp off; (nginx: compression disabled by default in modern versions)",
    reference_url="https://docs.telerik.com/fiddler/kb/CRIME-TLS-Compression",
    cve_correlations=[_cve("CVE-2012-4929", 4.3, "CRIME: TLS compression side-channel")],
    compliance_mappings=[_OWASP_A02, _NIST_TLS],
)

_NO_FALLBACK_SCSV = Finding(
    header="TLS",
    category=HeaderCategory.TRANSPORT,
    severity=Severity.MEDIUM,
    title="Missing TLS_FALLBACK_SCSV Protection",
    description="The server does not support TLS_FALLBACK_SCSV (RFC 7507), which protects against protocol downgrade attacks.",
    current_value="TLS_FALLBACK_SCSV not supported",
    recommendation="Update TLS library to support TLS_FALLBACK_SCSV.",
    example_value="TLS_FALLBACK_SCSV supported",
    reference_url="https://datatracker.ietf.org/doc/html/rfc7507",
    compliance_mappings=[_OWASP_A02],
)


# ── Registry ─────────────────────────────────────────────────────────────────

ALL_TLS_FINDINGS: dict[str, Finding] = {
    # Protocol
    "TLS_MISSING": _TLS_MISSING,
    "TLS_CONNECT_FAILED": _TLS_CONNECT_FAILED,
    "DEPRECATED_PROTOCOL_SSL2": _DEPRECATED_PROTOCOL_SSL2,
    "DEPRECATED_PROTOCOL_SSL3": _DEPRECATED_PROTOCOL_SSL3,
    "DEPRECATED_PROTOCOL_TLS10": _DEPRECATED_PROTOCOL_TLS10,
    "DEPRECATED_PROTOCOL_TLS11": _DEPRECATED_PROTOCOL_TLS11,
    "TLS13_NOT_SUPPORTED": _TLS13_NOT_SUPPORTED,
    # Cipher
    "WEAK_CIPHER_RC4": _WEAK_CIPHER_RC4,
    "WEAK_CIPHER_3DES": _WEAK_CIPHER_3DES,
    "WEAK_CIPHER_NULL": _WEAK_CIPHER_NULL,
    "WEAK_CIPHER_EXPORT": _WEAK_CIPHER_EXPORT,
    "NO_FORWARD_SECRECY": _NO_FORWARD_SECRECY,
    "WEAK_DH_PARAMS": _WEAK_DH_PARAMS,
    # Certificate
    "CERT_EXPIRED": _CERT_EXPIRED,
    "CERT_EXPIRING_SOON": _CERT_EXPIRING_SOON,
    "CERT_SELF_SIGNED": _CERT_SELF_SIGNED,
    "CERT_HOSTNAME_MISMATCH": _CERT_HOSTNAME_MISMATCH,
    "CERT_WEAK_SIGNATURE": _CERT_WEAK_SIGNATURE,
    "CERT_SHORT_KEY": _CERT_SHORT_KEY,
    "NO_OCSP_STAPLING": _NO_OCSP_STAPLING,
    # Vulnerability
    "HEARTBLEED": _HEARTBLEED,
    "ROBOT": _ROBOT,
    "OPENSSL_CCS_INJECTION": _OPENSSL_CCS_INJECTION,
    "TLS_COMPRESSION": _TLS_COMPRESSION,
    "NO_FALLBACK_SCSV": _NO_FALLBACK_SCSV,
}


def get_finding(finding_id: str) -> Optional[Finding]:
    """
    Get a copy of a TLS finding definition by ID.

    Returns a deep copy so callers can modify current_value
    without affecting the template.

    Returns None if the finding ID is not found.
    """
    template = ALL_TLS_FINDINGS.get(finding_id)
    if template is None:
        return None
    return copy.deepcopy(template)
