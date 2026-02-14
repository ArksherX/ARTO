#!/bin/bash

echo "🛡️  Tessera IAM - Production Deployment"
echo "========================================"
echo ""

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose not installed"
    exit 1
fi

echo "✅ Prerequisites OK"
echo ""

# Generate secure keys if not exists
if [ ! -f .env ]; then
    echo "🔑 Generating secure keys..."
    echo "TESSERA_SECRET_KEY=$(openssl rand -base64 48)" > .env
    echo "POSTGRES_PASSWORD=$(openssl rand -base64 32)" >> .env
    echo "✅ Keys generated"
fi

# Build and start services
echo ""
echo "🚀 Starting services..."
docker-compose up -d --build

# Wait for services
echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 10

# Initialize database
echo ""
echo "🔧 Initializing database..."
docker-compose exec tessera-api python setup_production_db.py

echo ""
echo "✅ Production deployment complete!"
echo ""
echo "📍 Services:"
echo "   API Server:   http://localhost:8000"
echo "   API Docs:     http://localhost:8000/docs"
echo "   Dashboard:    http://localhost:8501"
echo "   PostgreSQL:   localhost:5432"
echo "   Redis:        localhost:6379"
echo ""
echo "🔍 View logs:"
echo "   docker-compose logs -f tessera-api"
echo ""
echo "🛑 Stop services:"
echo "   docker-compose down"
