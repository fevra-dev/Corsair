"""pytest fixtures."""

import pytest


@pytest.fixture
def good_headers():
    """Headers with good security configuration."""
    return {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }


@pytest.fixture
def bad_headers():
    """Headers with security issues."""
    return {
        "X-Powered-By": "PHP/7.4.0",
        "Server": "Apache/2.4.41 (Ubuntu)",
    }
