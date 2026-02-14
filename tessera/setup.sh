#!/bin/bash
set -e

echo "🛡️  Tessera IAM Setup"
echo "===================="
echo ""

# Check Python
echo "📋 Checking Python version..."
python3 --version

# Create virtual environment
echo ""
echo "🐍 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "✅ Virtual environment created"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "✅ Dependencies installed"

# Generate secret key
echo ""
echo "🔐 Generating secret key..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Create .env file
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cat > .env << ENVEOF
# Tessera Configuration
TESSERA_SECRET_KEY=$SECRET_KEY
TESSERA_ALGORITHM=HS256
TESSERA_DEFAULT_TTL=300

# Redis (Optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# VerityFlux Integration (Optional)
VERITYFLUX_PATH=../verityflux-v2
VERITYFLUX_ENABLED=false

# Development
DEBUG=true
ENVEOF
    echo "✅ .env file created"
else
    echo "⚠️  .env already exists, skipping..."
fi

# Initialize registry
echo ""
echo "🤖 Initializing agent registry..."
python3 << PYEOF
import sys
sys.path.insert(0, '.')
from tessera.registry import TesseraRegistry

registry = TesseraRegistry()
print(f"✅ Registry initialized with {len(registry.agents)} agents")
PYEOF

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 Next steps:"
echo "   1. source venv/bin/activate"
echo "   2. python quickstart.py          # Test the system"
echo "   3. streamlit run web_ui/tessera_dashboard.py  # Launch UI"
echo ""
