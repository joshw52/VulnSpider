# Docker Setup for AI Web Crawler Security Server

## Quick Start

### Using Docker Compose (Recommended)
```bash
# Build and run the application
docker-compose up --build

# Run in background
docker-compose up -d --build

# View logs
docker-compose logs -f

# Stop the application
docker-compose down
```

### Using Docker directly
```bash
# Build the image
docker build -t ai-web-crawler-server ./server

# Run the container
docker run -p 5000:5000 ai-web-crawler-server

# Run in background
docker run -d -p 5000:5000 --name web-crawler ai-web-crawler-server
```

## Development

### Local Development with Docker
```bash
# Build development image
docker build -t ai-web-crawler-dev ./server

# Run with volume mounting for live reload
docker run -p 5000:5000 -v ${PWD}/server:/app ai-web-crawler-dev
```

### Environment Variables
- `FLASK_ENV`: Set to `production` for production builds
- `PYTHONUNBUFFERED`: Ensures Python output is sent straight to terminal

## Health Check
The container includes a health check endpoint at `/health` that returns:
```json
{
  "status": "healthy",
  "service": "ai_web_crawler_security"
}
```

## Security Features
- ✅ Non-root user execution
- ✅ Minimal base image (python:3.11-slim)
- ✅ No cache pip installations
- ✅ Health checks included
- ✅ Proper .dockerignore for smaller builds

## Production Deployment

### With Docker Compose
```bash
# Production deployment
FLASK_ENV=production docker-compose up -d --build
```

### Manual Deployment
```bash
# Build production image
docker build -t ai-web-crawler-prod ./server

# Run with restart policy
docker run -d \
  --name web-crawler-prod \
  --restart unless-stopped \
  -p 5000:5000 \
  -e FLASK_ENV=production \
  ai-web-crawler-prod
```

## Monitoring
```bash
# View container logs
docker logs web-crawler

# Monitor resource usage
docker stats web-crawler

# Check health
curl http://localhost:5000/health
```
