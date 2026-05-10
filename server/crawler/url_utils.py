import ipaddress
import socket

import requests
from urllib.parse import urlparse, urljoin


def _is_ssrf_safe(hostname: str) -> bool:
    """Return False if the hostname resolves to a private, loopback, or link-local address."""
    try:
        addresses = {r[4][0] for r in socket.getaddrinfo(hostname, None)}
    except socket.gaierror:
        return False
    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        except ValueError:
            return False
    return bool(addresses)


def safe_get(url, headers=None, timeout=10, max_redirects=10):
    """
    Drop-in replacement for requests.get() that validates every redirect hop
    against SSRF rules before following it.
    """
    for _ in range(max_redirects + 1):
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        if response.is_redirect:
            location = response.headers.get('Location', '')
            next_url = urljoin(url, location)
            parsed = urlparse(next_url)
            if parsed.scheme not in ('http', 'https'):
                raise requests.exceptions.InvalidURL(
                    f"Redirect to disallowed scheme blocked: {parsed.scheme}"
                )
            if not _is_ssrf_safe(parsed.hostname):
                raise requests.exceptions.ConnectionError(
                    f"Redirect to disallowed address blocked: {next_url}"
                )
            url = next_url
        else:
            return response
    raise requests.TooManyRedirects(f"Exceeded {max_redirects} redirects for {url}")


def categorize_url(href):
    """
    Categorize a URL/href into different types:
    - absolute: full URLs with scheme (http://example.com/page)
    - root-relative: URLs starting with / (/page.html)
    - relative: URLs without leading / (page.html, ../page.html)
    - fragment: URLs starting with # (#section)
    - protocol-relative: URLs starting with // (//example.com/page)
    - mailto/tel/etc: Special schemes
    """
    if not href or href.strip() == "":
        return "empty"

    href = href.strip()

    # Fragment/anchor links
    if href.startswith('#'):
        return "fragment"

    # Protocol-relative URLs
    if href.startswith('//'):
        return "protocol-relative"

    # Check if it has a scheme (absolute URL)
    parsed = urlparse(href)
    if parsed.scheme:
        if parsed.scheme in ['http', 'https']:
            return "absolute"
        elif parsed.scheme in ['mailto', 'tel', 'ftp', 'file']:
            return f"special-{parsed.scheme}"
        else:
            return "special-scheme"

    # Root-relative URLs (start with /)
    if href.startswith('/'):
        return "root-relative"

    # Query-only URLs
    if href.startswith('?'):
        return "query-only"

    # Everything else is relative
    return "relative"
