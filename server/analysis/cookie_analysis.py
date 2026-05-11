"""
Static analyzer for Set-Cookie response headers.
Flags missing or misconfigured HttpOnly, Secure, and SameSite attributes.
"""

from __future__ import annotations

import re


def _parse_cookie_header(raw: str) -> dict:
    """
    Parse a single Set-Cookie header value into its name and attribute flags.

    Returns a dict with:
      - name        (str)       : cookie name
      - httponly    (bool)      : HttpOnly flag present
      - secure      (bool)      : Secure flag present
      - samesite    (str|None)  : SameSite value ('Strict', 'Lax', 'None') or None
    """
    parts = [p.strip() for p in raw.split(';')]
    name = parts[0].split('=')[0].strip() if parts else '<unknown>'

    attrs = {p.lower() for p in parts[1:]}
    attr_str = '; '.join(parts[1:]).lower()

    httponly = any(p == 'httponly' for p in attrs)
    secure = any(p == 'secure' for p in attrs)

    samesite: str | None = None
    match = re.search(r'samesite=(\w+)', attr_str)
    if match:
        samesite = match.group(1).capitalize()

    return {"name": name, "httponly": httponly, "secure": secure, "samesite": samesite}


def analyze_cookies(response_headers: dict) -> list[dict]:
    """
    Analyze Set-Cookie headers from an HTTP response for missing security attributes.

    Args:
        response_headers: Mapping of header name to value. Because ``requests``
            exposes only the last Set-Cookie value through its normal dict
            interface, callers should pass ``response.raw.headers.getlist``
            results via the helper below; this function also accepts the plain
            dict and will process whatever Set-Cookie value is present.

    Returns:
        List of finding dicts, one per cookie that has at least one issue.
        Each dict contains:
          - name          (str)        : cookie name
          - raw           (str)        : the original Set-Cookie header value
          - issues        (list[dict]) : list of {severity, attribute, description, recommendation}
    """
    raw_cookies: list[str] = []

    # Accept either a plain dict (single value) or a list of raw header values
    if isinstance(response_headers, list):
        raw_cookies = response_headers
    else:
        normalized = {k.lower(): v for k, v in response_headers.items()}
        value = normalized.get('set-cookie')
        if value:
            raw_cookies = [value]

    findings = []

    for raw in raw_cookies:
        parsed = _parse_cookie_header(raw)
        issues = []

        if not parsed["httponly"]:
            issues.append({
                "severity": "medium",
                "attribute": "HttpOnly",
                "description": (
                    f"Cookie '{parsed['name']}' is missing the HttpOnly flag. "
                    "Without it, the cookie can be read by JavaScript, increasing "
                    "the impact of any XSS vulnerability on this page."
                ),
                "recommendation": "Add the HttpOnly attribute to this Set-Cookie directive.",
            })

        if not parsed["secure"]:
            issues.append({
                "severity": "medium",
                "attribute": "Secure",
                "description": (
                    f"Cookie '{parsed['name']}' is missing the Secure flag. "
                    "Without it, the cookie can be transmitted over unencrypted HTTP "
                    "connections, where it may be intercepted."
                ),
                "recommendation": "Add the Secure attribute to this Set-Cookie directive.",
            })

        samesite = parsed["samesite"]
        if samesite is None:
            issues.append({
                "severity": "low",
                "attribute": "SameSite",
                "description": (
                    f"Cookie '{parsed['name']}' has no SameSite attribute. "
                    "Browsers may then send it with cross-site requests, "
                    "leaving the application vulnerable to CSRF attacks."
                ),
                "recommendation": (
                    "Add SameSite=Lax (default for most apps) or SameSite=Strict. "
                    "Avoid SameSite=None unless cross-site access is deliberately required "
                    "(and pair it with Secure if so)."
                ),
            })
        elif samesite == "None" and not parsed["secure"]:
            issues.append({
                "severity": "medium",
                "attribute": "SameSite=None requires Secure",
                "description": (
                    f"Cookie '{parsed['name']}' uses SameSite=None but is missing the "
                    "Secure flag. Modern browsers will reject or ignore such cookies."
                ),
                "recommendation": "Add the Secure attribute when using SameSite=None.",
            })

        if issues:
            findings.append({
                "name": parsed["name"],
                "raw": raw,
                "issues": issues,
            })

    return findings


def analyze_cookies_from_response(response) -> list[dict]:
    """
    Convenience wrapper that extracts all Set-Cookie headers from a
    ``requests.Response`` object, handling multi-value headers correctly.
    """
    raw_cookies = response.raw.headers.getlist('Set-Cookie')
    return analyze_cookies(raw_cookies)
