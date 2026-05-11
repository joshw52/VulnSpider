import logging
import os

from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

from crawler.crawler import crawl_website
from crawler.url_utils import _is_ssrf_safe


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = Flask(__name__)

_cors_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://localhost:4000").split(",") if o.strip()]
CORS(app, resources={r"/crawl": {"origins": _cors_origins}})

# Headers that must not be forwarded to downstream requests
_HOP_BY_HOP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade",
}

@app.route('/crawl', methods=['POST'])
def crawl():
    data = request.get_json()
    if data is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    url = data.get('url')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Validate the URL
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        return jsonify({"error": "Invalid URL"}), 400

    if parsed_url.scheme not in ('http', 'https'):
        return jsonify({"error": "Only http and https URLs are allowed"}), 400

    # Block SSRF — reject URLs that resolve to private/loopback/link-local addresses
    if not _is_ssrf_safe(parsed_url.hostname):
        return jsonify({"error": "URL resolves to a disallowed address"}), 400

    # Strip hop-by-hop headers that must not be forwarded
    raw_headers = data.get('headers', {})
    if not isinstance(raw_headers, dict):
        return jsonify({"error": "'headers' must be an object"}), 400
    custom_headers = {
        k: v for k, v in raw_headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS
    }

    max_pages = data.get('max_pages', 50)
    if not isinstance(max_pages, int) or max_pages < 1:
        return jsonify({"error": "'max_pages' must be a positive integer"}), 400
    max_pages = min(max_pages, 200)

    max_depth = data.get('max_depth', None)
    if max_depth is not None:
        if not isinstance(max_depth, int) or max_depth < 1:
            return jsonify({"error": "'max_depth' must be a positive integer or omitted"}), 400
        max_depth = min(max_depth, 20)

    respect_robots = data.get('respect_robots', False)
    if not isinstance(respect_robots, bool):
        return jsonify({"error": "'respect_robots' must be a boolean"}), 400

    # Start crawling the website
    result = crawl_website(url, f"{parsed_url.scheme}://{parsed_url.netloc}", headers=custom_headers, max_pages=max_pages, max_depth=max_depth, respect_robots=respect_robots)

    return jsonify(result), 200

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "ai_web_crawler_security"}), 200

if __name__ == '__main__':
    app.run(debug=False)
