from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from urllib.parse import urlparse

from crawler.crawler import crawl_website


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

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "ai_web_crawler_security"}), 200

if __name__ == '__main__':
    app.run(debug=True)
