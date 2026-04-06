#!/bin/bash

# Exit on any error
set -e

# Wait for any dependencies (if needed)
echo "Starting AI Web Crawler Security Server..."

# Run database migrations or setup if needed
# python setup.py

# Start the Flask application
exec python -m flask run --host=0.0.0.0 --port=5000
