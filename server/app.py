from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

from crawler.crawler import crawl_website


app = Flask(__name__)

CORS(app, resources={r"/crawl": {"origins": ["http://localhost:5173", "http://localhost:4000"]}})

# Headers that must not be forwarded to downstream requests
_HOP_BY_HOP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade",
}

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

    # Strip hop-by-hop headers that must not be forwarded
    raw_headers = data.get('headers', {})
    if not isinstance(raw_headers, dict):
        return jsonify({"error": "'headers' must be an object"}), 400
    custom_headers = {
        k: v for k, v in raw_headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS
    }

    # Start crawling the website
    result = crawl_website(url, f"{parsed_url.scheme}://{parsed_url.netloc}", headers=custom_headers)

    return jsonify(result), 200

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "ai_web_crawler_security"}), 200

if __name__ == '__main__':
    app.run(debug=True)
