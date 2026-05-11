import base64
import logging

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

from analysis.code_analysis import scan_code_for_vulnerabilities
from analysis.header_analysis import analyze_headers
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


def crawl_website(start_url, base_url, headers=None, max_pages=50):
    parsed_base_url = urlparse(base_url)
    sites = []
    crawled_urls = set()
    queued_urls = set([start_url])
    urls_to_visit = [start_url]

    # Merge caller-supplied headers with the default User-Agent
    merged_headers = {**_DEFAULT_HEADERS, **(headers or {})}

    # Retrieve SSL certificate if HTTPS
    certificate = None
    if parsed_base_url.scheme == 'https':
        certificate = get_ssl_certificate(parsed_base_url.hostname)

    while urls_to_visit and len(crawled_urls) < max_pages:
        current_url = urls_to_visit.pop(0)
        if current_url in crawled_urls:
            continue

        try:
            page_data, soup = process_page(current_url, headers=merged_headers)
            crawled_urls.add(current_url)
            sites.append(page_data)

            # Discover new same-domain pages to crawl (once per page, not per link)
            for new_url in extract_links(soup, base_url):
                if new_url not in crawled_urls and new_url not in queued_urls:
                    queued_urls.add(new_url)
                    urls_to_visit.append(new_url)

        except requests.RequestException as e:
            logger.warning("Failed to fetch %s: %s", current_url, e)

    return {"certificate": certificate, "sites": sites}
