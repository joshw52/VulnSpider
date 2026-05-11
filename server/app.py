import json
import logging
import os

import requests as http_client
from flask import Flask, Response, request, jsonify, stream_with_context
from flask_cors import CORS
from urllib.parse import urlparse

from analysis.code_analysis import OLLAMA_BASE_URL, OLLAMA_MODEL
from crawler.crawler import crawl_website, crawl_website_stream
from crawler.url_utils import _is_ssrf_safe


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = Flask(__name__)

_cors_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://localhost:4000").split(",") if o.strip()]
# Match all routes so /models and any future endpoints are also covered
CORS(app, resources={r"/*": {"origins": _cors_origins}})

# Headers that must not be forwarded to downstream requests
_HOP_BY_HOP_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade",
}


def _validate_crawl_request(data):
    """
    Validate and extract crawl parameters from parsed request JSON.

    Returns (params_dict, None) on success, or (None, (response, status)) on failure.
    """
    if data is None:
        return None, (jsonify({"error": "Request body must be valid JSON"}), 400)

    url = data.get('url')
    if not url:
        return None, (jsonify({"error": "URL is required"}), 400)

    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        return None, (jsonify({"error": "Invalid URL"}), 400)

    if parsed_url.scheme not in ('http', 'https'):
        return None, (jsonify({"error": "Only http and https URLs are allowed"}), 400)

    if not _is_ssrf_safe(parsed_url.hostname):
        return None, (jsonify({"error": "URL resolves to a disallowed address"}), 400)

    raw_headers = data.get('headers', {})
    if not isinstance(raw_headers, dict):
        return None, (jsonify({"error": "'headers' must be an object"}), 400)
    custom_headers = {
        k: v for k, v in raw_headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS
    }

    max_pages = data.get('max_pages', 50)
    if not isinstance(max_pages, int) or max_pages < 1:
        return None, (jsonify({"error": "'max_pages' must be a positive integer"}), 400)
    max_pages = min(max_pages, 200)

    max_depth = data.get('max_depth', None)
    if max_depth is not None:
        if not isinstance(max_depth, int) or max_depth < 1:
            return None, (jsonify({"error": "'max_depth' must be a positive integer or omitted"}), 400)
        max_depth = min(max_depth, 20)

    respect_robots = data.get('respect_robots', False)
    if not isinstance(respect_robots, bool):
        return None, (jsonify({"error": "'respect_robots' must be a boolean"}), 400)

    model = data.get('model', OLLAMA_MODEL)
    if not isinstance(model, str) or not model.strip():
        return None, (jsonify({"error": "'model' must be a non-empty string"}), 400)

    return {
        "url": url,
        "base_url": f"{parsed_url.scheme}://{parsed_url.netloc}",
        "custom_headers": custom_headers,
        "max_pages": max_pages,
        "max_depth": max_depth,
        "respect_robots": respect_robots,
        "model": model,
    }, None


@app.route('/crawl', methods=['POST'])
def crawl():
    params, err = _validate_crawl_request(request.get_json())
    if err:
        return err

    result = crawl_website(
        params["url"], params["base_url"],
        headers=params["custom_headers"],
        max_pages=params["max_pages"],
        max_depth=params["max_depth"],
        respect_robots=params["respect_robots"],
        model=params["model"],
    )
    return jsonify(result), 200


@app.route('/crawl/stream', methods=['POST'])
def crawl_stream():
    params, err = _validate_crawl_request(request.get_json())
    if err:
        return err

    def generate():
        try:
            for event in crawl_website_stream(
                params["url"], params["base_url"],
                headers=params["custom_headers"],
                max_pages=params["max_pages"],
                max_depth=params["max_depth"],
                respect_robots=params["respect_robots"],
                model=params["model"],
            ):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route('/models', methods=['GET'])
def list_models():
    try:
        resp = http_client.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        return jsonify({"models": models, "default": OLLAMA_MODEL}), 200
    except http_client.RequestException as e:
        logger.warning("Failed to reach Ollama API: %s", e)
        return jsonify({"error": "Could not reach Ollama API", "models": [], "default": OLLAMA_MODEL}), 502


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "ai_web_crawler_security"}), 200

if __name__ == '__main__':
    app.run(debug=False)
