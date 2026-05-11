"""
Static rules-based analyzer for HTTP response headers.
Flags missing or misconfigured security headers.
"""

from __future__ import annotations

import re
from typing import Optional


def _validate_hsts(value: str) -> Optional[tuple[str, str]]:
    lower = value.lower()
    match = re.search(r"max-age=(\d+)", lower)
    if not match:
        return (
            "high",
            "HSTS header is present but max-age is missing or malformed.",
        )
    max_age = int(match.group(1))
    if max_age < 31_536_000:
        return (
            "medium",
            f"HSTS max-age is {max_age}s which is less than one year (31536000). "
            "Increase it for stronger protection.",
        )
    return None


def _validate_xfo(value: str) -> Optional[tuple[str, str]]:
    upper = value.strip().upper()
    if upper not in ("DENY", "SAMEORIGIN"):
        return (
            "medium",
            f"X-Frame-Options value '{value}' is not a recognised directive. Use DENY or SAMEORIGIN.",
        )
    return None


def _validate_xcto(value: str) -> Optional[tuple[str, str]]:
    if value.strip().lower() != "nosniff":
        return (
            "medium",
            f"X-Content-Type-Options should be 'nosniff', got '{value}'.",
        )
    return None


_RULES: list[dict] = [
    {
        "header": "Content-Security-Policy",
        "severity_missing": "high",
        "description": (
            "Content-Security-Policy (CSP) controls which resources a browser may load for "
            "a given page. Its absence leaves the page open to Cross-Site Scripting (XSS) "
            "and data-injection attacks."
        ),
        "recommendation": (
            "Add a Content-Security-Policy header. Start with a restrictive baseline such as "
            "\"default-src 'self'\" and expand directives only as required."
        ),
    },
    {
        "header": "Strict-Transport-Security",
        "severity_missing": "high",
        "description": (
            "HTTP Strict-Transport-Security (HSTS) instructs browsers to connect exclusively "
            "over HTTPS, preventing protocol-downgrade and man-in-the-middle attacks."
        ),
        "recommendation": (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'. "
            "Ensure the site is fully HTTPS before enabling this header."
        ),
        "validate": _validate_hsts,
    },
    {
        "header": "X-Frame-Options",
        "severity_missing": "medium",
        "description": (
            "X-Frame-Options prevents the page from being embedded in an <iframe>, "
            "mitigating clickjacking attacks."
        ),
        "recommendation": (
            "Set 'X-Frame-Options: DENY' (or 'SAMEORIGIN' if same-origin framing is required). "
            "Alternatively, use the 'frame-ancestors' directive in Content-Security-Policy."
        ),
        "validate": _validate_xfo,
    },
    {
        "header": "X-Content-Type-Options",
        "severity_missing": "medium",
        "description": (
            "X-Content-Type-Options: nosniff prevents browsers from MIME-sniffing a response "
            "away from the declared content type, reducing the risk of drive-by downloads and "
            "content-type confusion attacks."
        ),
        "recommendation": "Set 'X-Content-Type-Options: nosniff'.",
        "validate": _validate_xcto,
    },
    {
        "header": "Referrer-Policy",
        "severity_missing": "low",
        "description": (
            "Referrer-Policy controls how much referrer information is included with requests. "
            "Without it, browsers may leak sensitive URL paths or query parameters to "
            "third-party origins."
        ),
        "recommendation": (
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' or a stricter value "
            "such as 'no-referrer'."
        ),
    },
    {
        "header": "Permissions-Policy",
        "severity_missing": "low",
        "description": (
            "Permissions-Policy (formerly Feature-Policy) restricts access to browser APIs "
            "such as camera, microphone, and geolocation. Its absence means the page may grant "
            "the broadest possible permissions."
        ),
        "recommendation": (
            "Add a Permissions-Policy header that disables APIs your site does not use, e.g. "
            "'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
        ),
    },
]


def analyze_headers(headers: dict) -> list[dict]:
    """
    Analyze HTTP response headers for missing or misconfigured security headers.

    Args:
        headers: Mapping of header name to value (case-insensitive lookup handled internally).

    Returns:
        List of finding dicts. Each dict contains:
          - header         (str)       : canonical header name
          - present        (bool)      : whether the header was found in the response
          - value          (str|None)  : the header's value, or None if absent
          - severity       (str)       : 'high' | 'medium' | 'low'
          - description    (str)       : explanation of the issue
          - recommendation (str)       : remediation advice
    """
    normalized = {k.lower(): v for k, v in headers.items()}
    findings = []

    for rule in _RULES:
        header_lower = rule["header"].lower()
        value = normalized.get(header_lower)

        if value is None:
            findings.append({
                "header": rule["header"],
                "present": False,
                "value": None,
                "severity": rule["severity_missing"],
                "description": rule["description"],
                "recommendation": rule["recommendation"],
            })
        else:
            validator = rule.get("validate")
            if validator:
                issue = validator(value)
                if issue:
                    sev, detail = issue
                    findings.append({
                        "header": rule["header"],
                        "present": True,
                        "value": value,
                        "severity": sev,
                        "description": detail,
                        "recommendation": rule["recommendation"],
                    })
            # Header present with no validator (or passing validation) → no finding

    return findings
