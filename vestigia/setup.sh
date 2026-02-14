#!/bin/bash

echo "🗃️  Setting up Vestigia Production..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create data directories
mkdir -p data/history backups

# Generate secret salt
echo "VESTIGIA_SECRET_SALT=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" > .env

echo ""
echo "✅ Vestigia Production setup complete!"
echo ""
echo "Quick Start:"
echo "  1. source venv/bin/activate"
echo "  2. python cli.py log agent_001 SECURITY_SCAN SUCCESS 'Test event'"
echo "  3. python cli.py verify"
echo "  4. python cli.py stats"
echo "  5. python hardening.py --status"
echo "  6. streamlit run web_ui/dashboard.py"
