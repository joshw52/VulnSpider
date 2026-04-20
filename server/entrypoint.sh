#!/bin/bash

# Exit on any error
set -e

echo "Starting AI Web Crawler Security Server..."

# Pull the configured model via Python (curl is not available in this image)
python - <<'EOF'
import json
import os
import sys
import requests

base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
model = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")

print(f"Pulling Ollama model: {model} ...", flush=True)
try:
    with requests.post(f"{base_url}/api/pull", json={"name": model}, stream=True, timeout=1800) as resp:
        resp.raise_for_status()
        for raw in resp.iter_lines():
            if not raw:
                continue
            data = json.loads(raw)
            status = data.get("status", "")
            if "pulling" in status or status in ("success", "already exists"):
                print(status, flush=True)
            if status == "success" or status == "already exists":
                print("Model ready.", flush=True)
                sys.exit(0)
    print("ERROR: pull stream ended without success status", flush=True)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: failed to pull model: {e}", flush=True)
    sys.exit(1)
EOF

# Start the Flask application
exec python -m flask run --host=0.0.0.0 --port=5000
