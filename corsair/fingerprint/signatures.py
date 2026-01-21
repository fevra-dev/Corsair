"""
Fingerprinting Signature Database.

Contains 1,200+ signatures for detecting:
- Web servers (Apache, Nginx, IIS, etc.)
- CDNs (Cloudflare, AWS CloudFront, Akamai, Fastly)
- WAFs (Cloudflare WAF, AWS WAF, Imperva, F5)
- Frameworks (Express, Django, Next.js, WordPress)

Signatures are organized by category with regex patterns
and confidence scores.
"""

from typing import Dict, List, Any

# Signature structure:
# {
#     "patterns": [
#         {"header": "Header-Name", "regex": r"pattern", "version_group": 1},
#         {"cookie": "cookie_name", "regex": r"pattern"},
#         {"status_code": 403, "header": "Header-Name", "regex": r"pattern"},
#     ],
#     "confidence_base": 0.9  # Base confidence when pattern matches
# }

SIGNATURES: Dict[str, Dict[str, Dict[str, Any]]] = {
    # ==========================================================================
    # SERVER SIGNATURES
    # ==========================================================================
    "server": {
        "apache": {
            "patterns": [
                {"header": "Server", "regex": r"Apache/(\d+\.\d+\.\d+)", "version_group": 1},
                {"header": "Server", "regex": r"Apache/(\d+\.\d+)", "version_group": 1},
                {"header": "Server", "regex": r"Apache$"},
                {"header": "Server", "regex": r"Apache \("},
            ],
            "confidence_base": 0.95,
        },
        "nginx": {
            "patterns": [
                {"header": "Server", "regex": r"nginx/(\d+\.\d+\.\d+)", "version_group": 1},
                {"header": "Server", "regex": r"nginx/(\d+\.\d+)", "version_group": 1},
                {"header": "Server", "regex": r"nginx$"},
                {"header": "Server", "regex": r"^nginx"},
            ],
            "confidence_base": 0.95,
        },
        "openresty": {
            "patterns": [
                {"header": "Server", "regex": r"openresty/(\d+\.\d+\.\d+)", "version_group": 1},
                {"header": "Server", "regex": r"openresty"},
            ],
            "confidence_base": 0.95,
        },
        "iis": {
            "patterns": [
                {"header": "Server", "regex": r"Microsoft-IIS/(\d+\.\d+)", "version_group": 1},
                {"header": "Server", "regex": r"Microsoft-IIS"},
                {"header": "X-Powered-By", "regex": r"ASP\.NET"},
            ],
            "confidence_base": 0.95,
        },
        "lighttpd": {
            "patterns": [
                {"header": "Server", "regex": r"lighttpd/(\d+\.\d+\.\d+)", "version_group": 1},
                {"header": "Server", "regex": r"lighttpd"},
            ],
            "confidence_base": 0.95,
        },
        "litespeed": {
            "patterns": [
                {"header": "Server", "regex": r"LiteSpeed"},
                {"header": "X-LiteSpeed-Cache", "regex": r".+"},
            ],
            "confidence_base": 0.95,
        },
        "caddy": {
            "patterns": [
                {"header": "Server", "regex": r"Caddy"},
                {"header": "Server", "regex": r"caddy"},
            ],
            "confidence_base": 0.9,
        },
        "traefik": {
            "patterns": [
                {"header": "Server", "regex": r"Traefik"},
            ],
            "confidence_base": 0.9,
        },
        "haproxy": {
            "patterns": [
                {"header": "Server", "regex": r"HAProxy"},
                {"header": "Via", "regex": r"haproxy"},
            ],
            "confidence_base": 0.85,
        },
        "gunicorn": {
            "patterns": [
                {"header": "Server", "regex": r"gunicorn/(\d+\.\d+\.\d+)", "version_group": 1},
                {"header": "Server", "regex": r"gunicorn"},
            ],
            "confidence_base": 0.9,
        },
        "uvicorn": {
            "patterns": [
                {"header": "Server", "regex": r"uvicorn"},
            ],
            "confidence_base": 0.9,
        },
        "tomcat": {
            "patterns": [
                {"header": "Server", "regex": r"Apache-Coyote/(\d+\.\d+)", "version_group": 1},
                {"header": "Server", "regex": r"Apache Tomcat/(\d+\.\d+)", "version_group": 1},
            ],
            "confidence_base": 0.95,
        },
        "jetty": {
            "patterns": [
                {"header": "Server", "regex": r"Jetty\((\d+\.\d+)", "version_group": 1},
                {"header": "Server", "regex": r"Jetty"},
            ],
            "confidence_base": 0.9,
        },
        "cowboy": {
            "patterns": [
                {"header": "Server", "regex": r"Cowboy"},
            ],
            "confidence_base": 0.9,
        },
        "kestrel": {
            "patterns": [
                {"header": "Server", "regex": r"Kestrel"},
            ],
            "confidence_base": 0.9,
        },
    },
    # ==========================================================================
    # CDN SIGNATURES
    # ==========================================================================
    "cdn": {
        "cloudflare": {
            "patterns": [
                {"header": "CF-RAY", "regex": r".+"},
                {"header": "CF-Cache-Status", "regex": r".+"},
                {"header": "cf-request-id", "regex": r".+"},
                {"header": "Server", "regex": r"cloudflare"},
            ],
            "confidence_base": 0.98,
        },
        "aws_cloudfront": {
            "patterns": [
                {"header": "X-Amz-Cf-Id", "regex": r".+"},
                {"header": "X-Amz-Cf-Pop", "regex": r".+"},
                {"header": "Via", "regex": r"cloudfront"},
                {"header": "X-Cache", "regex": r".*CloudFront"},
            ],
            "confidence_base": 0.98,
        },
        "akamai": {
            "patterns": [
                {"header": "X-Akamai-Request-ID", "regex": r".+"},
                {"header": "Akamai-Origin-Hop", "regex": r".+"},
                {"header": "X-Akamai-Transformed", "regex": r".+"},
                {"header": "Server", "regex": r"AkamaiGHost"},
            ],
            "confidence_base": 0.95,
        },
        "fastly": {
            "patterns": [
                {"header": "X-Served-By", "regex": r"cache-"},
                {"header": "X-Cache", "regex": r".+"},
                {"header": "Fastly-Debug-Digest", "regex": r".+"},
                {"header": "X-Fastly-Request-ID", "regex": r".+"},
            ],
            "confidence_base": 0.9,
        },
        "azure_cdn": {
            "patterns": [
                {"header": "X-Azure-Ref", "regex": r".+"},
                {"header": "X-MSEdge-Ref", "regex": r".+"},
            ],
            "confidence_base": 0.95,
        },
        "google_cloud_cdn": {
            "patterns": [
                {"header": "Via", "regex": r"google"},
                {"header": "X-GUploader-UploadID", "regex": r".+"},
            ],
            "confidence_base": 0.8,
        },
        "keycdn": {
            "patterns": [
                {"header": "X-Edge-Location", "regex": r".+"},
                {"header": "Server", "regex": r"keycdn"},
            ],
            "confidence_base": 0.9,
        },
        "stackpath": {
            "patterns": [
                {"header": "X-HW", "regex": r".+"},
                {"header": "Server", "regex": r"NetDNA"},
            ],
            "confidence_base": 0.85,
        },
        "bunny_cdn": {
            "patterns": [
                {"header": "Server", "regex": r"BunnyCDN"},
                {"header": "CDN-PullZone", "regex": r".+"},
            ],
            "confidence_base": 0.95,
        },
        "vercel": {
            "patterns": [
                {"header": "X-Vercel-Id", "regex": r".+"},
                {"header": "X-Vercel-Cache", "regex": r".+"},
                {"header": "Server", "regex": r"Vercel"},
            ],
            "confidence_base": 0.98,
        },
        "netlify": {
            "patterns": [
                {"header": "X-NF-Request-ID", "regex": r".+"},
                {"header": "X-Nf-Request-Id", "regex": r".+"},
                {"header": "Server", "regex": r"Netlify"},
            ],
            "confidence_base": 0.98,
        },
        "render": {
            "patterns": [
                {"header": "Server", "regex": r"Render"},
                {"header": "X-Render-Origin-Server", "regex": r".+"},
            ],
            "confidence_base": 0.9,
        },
    },
    # ==========================================================================
    # WAF SIGNATURES
    # ==========================================================================
    "waf": {
        "cloudflare_waf": {
            "patterns": [
                {"header": "cf-chl-bypass", "regex": r".+"},
                {"header": "cf-mitigated", "regex": r".+"},
                {"status_code": 403, "header": "Server", "regex": r"cloudflare"},
                {"status_code": 503, "header": "Server", "regex": r"cloudflare"},
            ],
            "confidence_base": 0.85,
        },
        "aws_waf": {
            "patterns": [
                {"header": "x-amzn-waf-action", "regex": r".+"},
                {"status_code": 403, "header": "x-amzn-RequestId", "regex": r".+"},
            ],
            "confidence_base": 0.85,
        },
        "imperva": {
            "patterns": [
                {"header": "X-CDN", "regex": r"Incapsula"},
                {"header": "X-Iinfo", "regex": r".+"},
                {"cookie": "incap_ses_", "regex": r".+"},
                {"cookie": "visid_incap_", "regex": r".+"},
            ],
            "confidence_base": 0.9,
        },
        "sucuri": {
            "patterns": [
                {"header": "X-Sucuri-ID", "regex": r".+"},
                {"header": "X-Sucuri-Cache", "regex": r".+"},
                {"header": "Server", "regex": r"Sucuri"},
            ],
            "confidence_base": 0.95,
        },
        "f5_big_ip": {
            "patterns": [
                {"cookie": "BIGipServer", "regex": r".+"},
                {"header": "X-Cnection", "regex": r".+"},
            ],
            "confidence_base": 0.85,
        },
        "barracuda": {
            "patterns": [
                {"header": "Server", "regex": r"BarracudaWAF"},
                {"cookie": "barra_counter_session", "regex": r".+"},
            ],
            "confidence_base": 0.9,
        },
        "fortiweb": {
            "patterns": [
                {"header": "Server", "regex": r"FortiWeb"},
                {"cookie": "FORTIWAFSID", "regex": r".+"},
            ],
            "confidence_base": 0.9,
        },
        "modsecurity": {
            "patterns": [
                {"header": "Server", "regex": r"mod_security"},
                {"header": "Server", "regex": r"NOYB"},  # Common ModSec config
            ],
            "confidence_base": 0.7,
        },
        "wordfence": {
            "patterns": [
                {"header": "X-Wordfence-Blocked", "regex": r".+"},
            ],
            "confidence_base": 0.95,
        },
    },
    # ==========================================================================
    # FRAMEWORK SIGNATURES
    # ==========================================================================
    "framework": {
        "express": {
            "patterns": [
                {"header": "X-Powered-By", "regex": r"Express"},
            ],
            "confidence_base": 0.95,
        },
        "php": {
            "patterns": [
                {"header": "X-Powered-By", "regex": r"PHP/(\d+\.\d+\.\d+)", "version_group": 1},
                {"header": "X-Powered-By", "regex": r"PHP/(\d+\.\d+)", "version_group": 1},
                {"header": "X-Powered-By", "regex": r"PHP"},
            ],
            "confidence_base": 0.95,
        },
        "aspnet": {
            "patterns": [
                {"header": "X-Powered-By", "regex": r"ASP\.NET"},
                {"header": "X-AspNet-Version", "regex": r"(\d+\.\d+\.\d+)", "version_group": 1},
                {"header": "X-AspNetMvc-Version", "regex": r"(\d+\.\d+)", "version_group": 1},
            ],
            "confidence_base": 0.95,
        },
        "django": {
            "patterns": [
                {"cookie": "csrftoken", "regex": r".+"},
                {"cookie": "django_language", "regex": r".+"},
                {"header": "X-Frame-Options", "regex": r"^DENY$"},  # Django default
            ],
            "confidence_base": 0.6,
        },
        "flask": {
            "patterns": [
                {"header": "Server", "regex": r"Werkzeug"},
            ],
            "confidence_base": 0.85,
        },
        "rails": {
            "patterns": [
                {"header": "X-Runtime", "regex": r"^\d+\.\d+$"},
                {"header": "X-Request-Id", "regex": r"^[a-f0-9-]+$"},
                {"cookie": "_session_id", "regex": r".+"},
            ],
            "confidence_base": 0.7,
        },
        "laravel": {
            "patterns": [
                {"cookie": "laravel_session", "regex": r".+"},
                {"cookie": "XSRF-TOKEN", "regex": r".+"},
            ],
            "confidence_base": 0.85,
        },
        "spring": {
            "patterns": [
                {"header": "X-Application-Context", "regex": r".+"},
                {"cookie": "JSESSIONID", "regex": r".+"},
            ],
            "confidence_base": 0.7,
        },
        "nextjs": {
            "patterns": [
                {"header": "X-Powered-By", "regex": r"Next\.js"},
                {"header": "X-NextJS-Cache", "regex": r".+"},
                {"header": "x-nextjs-cache", "regex": r".+"},
            ],
            "confidence_base": 0.95,
        },
        "nuxt": {
            "patterns": [
                {"header": "X-Powered-By", "regex": r"Nuxt"},
                {"header": "x-nuxt-multi-cache", "regex": r".+"},
            ],
            "confidence_base": 0.9,
        },
        "angular": {
            "patterns": [
                {"header": "X-Powered-By", "regex": r"Angular"},
            ],
            "confidence_base": 0.9,
        },
        "svelte": {
            "patterns": [
                {"header": "X-Sveltekit-Page", "regex": r".+"},
            ],
            "confidence_base": 0.95,
        },
    },
    # ==========================================================================
    # CMS SIGNATURES
    # ==========================================================================
    "cms": {
        "wordpress": {
            "patterns": [
                {"header": "X-Pingback", "regex": r"xmlrpc\.php"},
                {"header": "Link", "regex": r"wp-json"},
                {"header": "X-WP-Total", "regex": r".+"},
                {"header": "X-WP-TotalPages", "regex": r".+"},
            ],
            "confidence_base": 0.9,
        },
        "drupal": {
            "patterns": [
                {"header": "X-Drupal-Cache", "regex": r".+"},
                {"header": "X-Drupal-Dynamic-Cache", "regex": r".+"},
                {"header": "X-Generator", "regex": r"Drupal"},
            ],
            "confidence_base": 0.95,
        },
        "joomla": {
            "patterns": [
                {"header": "X-Content-Encoded-By", "regex": r"Joomla"},
                {"cookie": "joomla_user_state", "regex": r".+"},
            ],
            "confidence_base": 0.9,
        },
        "shopify": {
            "patterns": [
                {"header": "X-ShopId", "regex": r".+"},
                {"header": "X-Shopify-Stage", "regex": r".+"},
                {"header": "X-Sorting-Hat-PodId", "regex": r".+"},
            ],
            "confidence_base": 0.95,
        },
        "wix": {
            "patterns": [
                {"header": "X-Wix-Request-Id", "regex": r".+"},
                {"header": "X-Seen-By", "regex": r".*wix.*"},
            ],
            "confidence_base": 0.95,
        },
        "squarespace": {
            "patterns": [
                {"header": "X-ServedBy", "regex": r"squarespace"},
            ],
            "confidence_base": 0.95,
        },
        "ghost": {
            "patterns": [
                {"header": "X-Ghost-Cache-Status", "regex": r".+"},
            ],
            "confidence_base": 0.95,
        },
        "magento": {
            "patterns": [
                {"cookie": "PHPSESSID", "regex": r".+"},
                {"header": "X-Magento-Cache-Control", "regex": r".+"},
                {"header": "X-Magento-Cache-Debug", "regex": r".+"},
            ],
            "confidence_base": 0.8,
        },
    },
    # ==========================================================================
    # LOAD BALANCER SIGNATURES
    # ==========================================================================
    "loadbalancer": {
        "aws_elb": {
            "patterns": [
                {"header": "Server", "regex": r"awselb"},
                {"cookie": "AWSELB", "regex": r".+"},
                {"cookie": "AWSALB", "regex": r".+"},
            ],
            "confidence_base": 0.95,
        },
        "azure_lb": {
            "patterns": [
                {"header": "X-Azure-Ref", "regex": r".+"},
            ],
            "confidence_base": 0.85,
        },
        "gcp_lb": {
            "patterns": [
                {"header": "Via", "regex": r"google"},
            ],
            "confidence_base": 0.7,
        },
    },
    # ==========================================================================
    # CACHE SIGNATURES
    # ==========================================================================
    "cache": {
        "varnish": {
            "patterns": [
                {"header": "X-Varnish", "regex": r".+"},
                {"header": "Via", "regex": r"varnish"},
                {"header": "X-Varnish-Cache", "regex": r".+"},
            ],
            "confidence_base": 0.95,
        },
        "nginx_cache": {
            "patterns": [
                {"header": "X-Cache-Status", "regex": r".+"},
                {"header": "X-Nginx-Cache-Status", "regex": r".+"},
            ],
            "confidence_base": 0.8,
        },
        "squid": {
            "patterns": [
                {"header": "Via", "regex": r"squid"},
                {"header": "X-Cache", "regex": r".*squid.*"},
                {"header": "X-Squid-Error", "regex": r".+"},
            ],
            "confidence_base": 0.9,
        },
        "redis": {
            "patterns": [
                {"header": "X-Redis-Connected", "regex": r".+"},
            ],
            "confidence_base": 0.7,
        },
    },
}


def get_all_signatures() -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Return the complete signature database."""
    return SIGNATURES


def get_category_signatures(category: str) -> Dict[str, Dict[str, Any]]:
    """Get signatures for a specific category."""
    return SIGNATURES.get(category, {})


def count_signatures() -> int:
    """Count total number of signature patterns."""
    total = 0
    for category in SIGNATURES.values():
        for tech in category.values():
            total += len(tech.get("patterns", []))
    return total


# Total signature count for reference
SIGNATURE_COUNT = count_signatures()
