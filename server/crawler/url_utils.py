from urllib.parse import urlparse


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
