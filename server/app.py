from flask import Flask, request, jsonify
from flask_cors import CORS
from bs4 import BeautifulSoup
import base64
import requests
import logging
import socket
import ssl
from urllib.parse import urlparse, urljoin

from analysis.code_analysis import scan_code_for_vulnerabilities


def get_ssl_certificate(hostname, port=443):
    """Retrieve SSL certificate info for an HTTPS host."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception as e:
        print(f"Could not retrieve SSL certificate for {hostname}: {e}")
        return None


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


app = Flask(__name__)

CORS(app, resources={r"/crawl": {"origins": ["http://localhost:5173", "http://localhost:4000"]}})
logging.getLogger('flask_cors').level = logging.WARNING

@app.route('/crawl', methods=['POST'])
def crawl():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Validate the URL
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        return jsonify({"error": "Invalid URL"}), 400

    # Start crawling the website
    result = crawl_website(url, f"{parsed_url.scheme}://{parsed_url.netloc}")
    
    return jsonify(result), 200

def crawl_website(start_url, base_url):
    parsed_base_url = urlparse(base_url)
    sites = []
    crawled_urls = set()
    queued_urls = set([start_url])
    urls_to_visit = [start_url]

    # Retrieve SSL certificate if HTTPS
    certificate = None
    if parsed_base_url.scheme == 'https':
        certificate = get_ssl_certificate(parsed_base_url.hostname)

    while urls_to_visit:
        current_url = urls_to_visit.pop(0)
        if current_url in crawled_urls:
            continue

        try:
            page_data, raw_html = process_page(current_url)
            crawled_urls.add(current_url)
            sites.append(page_data)

            # Discover new same-domain pages to crawl (once per page, not per link)
            for new_url in extract_links(raw_html, base_url):
                if new_url not in crawled_urls and new_url not in queued_urls:
                    queued_urls.add(new_url)
                    urls_to_visit.append(new_url)

        except requests.RequestException as e:
            print(f"Failed to fetch {current_url}: {e}")

    return {"certificate": certificate, "sites": sites}

def process_page(url):
    response = requests.get(url, timeout=10)
    parsed_url = urlparse(url)
    raw_html = response.text

    page_data = {
        "path": parsed_url.path or "/",
        "html_content": base64.b64encode(raw_html.encode('utf-8')).decode('utf-8'),
        "links": [],
        "response_headers": [f"{k}: {v}" for k, v in response.headers.items()],
        "code_analysis": scan_code_for_vulnerabilities(raw_html).get("results", []),
    }

    soup = BeautifulSoup(raw_html, 'html.parser')

    # Collect hrefs from standard and framework-specific link attributes
    # 'to' is scoped to router-link/link/navlink tags to avoid false positives
    link_attrs = ['href', 'routerlink', 'routerLink', 'ng-href', 'data-href', 'data-url']
    router_to_tags = {'router-link', 'link', 'navlink'}
    seen_links = set()
    for tag in soup.find_all(True):
        attrs_to_check = list(link_attrs)
        if tag.name in router_to_tags:
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

    return page_data, raw_html

def extract_links(html_content, base_url):
    soup = BeautifulSoup(html_content, 'html.parser')
    links = []
    parsed_base = urlparse(base_url)
    seen = set()

    link_attrs = ['href', 'routerlink', 'routerLink', 'ng-href', 'data-href', 'data-url']
    router_to_tags = {'router-link', 'link', 'navlink'}
    for tag in soup.find_all(True):
        attrs_to_check = list(link_attrs)
        if tag.name in router_to_tags:
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
                    print(f"Error processing link {href}: {e}")

    return links

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "ai_web_crawler_security"}), 200

if __name__ == '__main__':
    app.run(debug=True)
