import base64
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

from analysis.code_analysis import scan_code_for_vulnerabilities
from analysis.cookie_analysis import analyze_cookies_from_response
from analysis.header_analysis import analyze_headers
from crawler.robots_utils import fetch_robots_txt, is_disallowed
from crawler.ssl_utils import get_ssl_certificate
from crawler.url_utils import categorize_url, safe_get

logger = logging.getLogger(__name__)

_DEFAULT_HEADERS = {
    "User-Agent": "ai-web-crawler-security/1.0 (security scanner)",
}

_LINK_ATTRS = ['href', 'routerlink', 'routerLink', 'ng-href', 'data-href', 'data-url']
_ROUTER_TO_TAGS = {'router-link', 'link', 'navlink'}


def fetch_linked_scripts(soup, page_url, headers=None):
    """Fetch and scan same-domain JS files referenced by <script src>."""
    parsed_page = urlparse(page_url)
    results = []

    for tag in soup.find_all('script', src=True):
        src = tag['src']
        full_url = urljoin(page_url, src)
        parsed_src = urlparse(full_url)

        # Only fetch same-domain scripts to prevent SSRF against arbitrary external hosts
        if parsed_src.netloc != parsed_page.netloc:
            continue

        try:
            js_response = safe_get(full_url, headers=headers, timeout=10)
            js_response.raise_for_status()
            script_findings = scan_code_for_vulnerabilities(js_response.text, content_type="js").get("results", [])
            for finding in script_findings:
                finding["source"] = parsed_src.path
            results.extend(script_findings)
        except requests.RequestException as e:
            logger.warning("Failed to fetch linked script %s: %s", full_url, e)

    return results


def process_page(url, headers=None):
    response = safe_get(url, headers=headers, timeout=10)
    response.raise_for_status()
    parsed_url = urlparse(url)
    raw_html = response.text

    # Parse once; reuse soup for link collection and script fetching
    soup = BeautifulSoup(raw_html, 'html.parser')

    html_findings = scan_code_for_vulnerabilities(raw_html).get("results", [])
    script_findings = fetch_linked_scripts(soup, url, headers=headers)

    page_data = {
        "path": parsed_url.path or "/",
        "html_content": base64.b64encode(raw_html.encode('utf-8')).decode('utf-8'),
        "links": [],
        "response_headers": [f"{k}: {v}" for k, v in response.headers.items()],
        "code_analysis": html_findings + script_findings,
        "header_analysis": analyze_headers(dict(response.headers)),
        "cookie_analysis": analyze_cookies_from_response(response),
    }

    # Collect hrefs from standard and framework-specific link attributes
    # 'to' is scoped to router-link/link/navlink tags to avoid false positives
    seen_links = set()
    for tag in soup.find_all(True):
        attrs_to_check = list(_LINK_ATTRS)
        if tag.name in _ROUTER_TO_TAGS:
            attrs_to_check.append('to')
        for attr in attrs_to_check:
            value = tag.get(attr)
            if value and value not in seen_links:
                seen_links.add(value)
                url_type = categorize_url(value)
                simplified_type = "absolute" if url_type == "absolute" else "relative"
                page_data["links"].append({
                    "type": simplified_type,
                    "link": value,
                })

    return page_data, soup


def extract_links(soup, base_url):
    links = []
    parsed_base = urlparse(base_url)
    seen = set()

    link_attrs = _LINK_ATTRS + ['src']
    for tag in soup.find_all(True):
        attrs_to_check = list(link_attrs)
        if tag.name in _ROUTER_TO_TAGS:
            attrs_to_check.append('to')
        for attr in attrs_to_check:
            href = tag.get(attr)
            if not href or href in seen:
                continue
            seen.add(href)
            url_type = categorize_url(href)

            if url_type in ['absolute', 'root-relative', 'relative']:
                try:
                    full_url = urljoin(base_url, href)
                    parsed_url = urlparse(full_url)

                    if parsed_url.netloc == parsed_base.netloc:
                        links.append(full_url)
                except Exception as e:
                    logger.warning("Error processing link %s: %s", href, e)

    return links


def crawl_website_stream(start_url, base_url, headers=None, max_pages=50, max_depth=None, respect_robots=False, max_workers=5):
    """
    Generator that yields SSE event dicts as pages are crawled.

    Yields:
        {"type": "page", "page": <page_data>}   — once per completed page
        {"type": "done", "certificate": ..., "robots_txt": ...}  — final event
    """
    parsed_base_url = urlparse(base_url)
    crawled_urls = set()
    queued_urls = {start_url}
    # Frontier stores (url, depth) tuples — depth 0 is the start URL
    frontier = [(start_url, 0)]

    # Merge caller-supplied headers with the default User-Agent
    merged_headers = {**_DEFAULT_HEADERS, **(headers or {})}

    # Retrieve SSL certificate if HTTPS
    certificate = None
    if parsed_base_url.scheme == 'https':
        certificate = get_ssl_certificate(parsed_base_url.hostname)

    # Fetch and parse robots.txt at crawl start
    robots_txt = fetch_robots_txt(base_url, headers=merged_headers)

    def _is_allowed(url):
        if not (respect_robots and robots_txt["found"]):
            return True
        path = urlparse(url).path or '/'
        if is_disallowed(path, robots_txt["rules"]):
            logger.info("Skipping %s (disallowed by robots.txt)", url)
            return False
        return True

    while frontier and len(crawled_urls) < max_pages:
        remaining = max_pages - len(crawled_urls)
        to_process = frontier[:remaining]
        frontier = frontier[remaining:]
        batch = [(url, depth) for url, depth in to_process if _is_allowed(url)]

        if not batch:
            continue

        with ThreadPoolExecutor(max_workers=min(max_workers, len(batch))) as executor:
            future_to_url_depth = {
                executor.submit(process_page, url, merged_headers): (url, depth)
                for url, depth in batch
            }
            for future in as_completed(future_to_url_depth):
                url, depth = future_to_url_depth[future]
                try:
                    page_data, soup = future.result()
                    crawled_urls.add(url)
                    yield {"type": "page", "page": page_data}

                    if max_depth is None or depth < max_depth:
                        for new_url in extract_links(soup, base_url):
                            if new_url not in crawled_urls and new_url not in queued_urls:
                                queued_urls.add(new_url)
                                frontier.append((new_url, depth + 1))

                except requests.RequestException as e:
                    logger.warning("Failed to fetch %s: %s", url, e)

    yield {"type": "done", "certificate": certificate, "robots_txt": robots_txt}


def crawl_website(start_url, base_url, headers=None, max_pages=50, max_depth=None, respect_robots=False, max_workers=5):
    sites = []
    certificate = None
    robots_txt = None
    for event in crawl_website_stream(start_url, base_url, headers=headers, max_pages=max_pages, max_depth=max_depth, respect_robots=respect_robots, max_workers=max_workers):
        if event["type"] == "page":
            sites.append(event["page"])
        elif event["type"] == "done":
            certificate = event["certificate"]
            robots_txt = event["robots_txt"]
    return {"certificate": certificate, "sites": sites, "robots_txt": robots_txt}
