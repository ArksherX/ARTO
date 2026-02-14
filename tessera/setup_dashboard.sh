#!/bin/bash
# setup_dashboard.sh - Quick setup for Tessera Web Dashboard

set -e

echo "🛡️  Tessera IAM Dashboard Setup"
echo "================================"
echo ""

# Check if in correct directory
if [ ! -d "tessera" ]; then
    echo "❌ Error: Must be run from tessera/ directory"
    echo "Usage: cd ~/ml-redteam/tessera && ./setup_dashboard.sh"
    exit 1
fi

# Create web_ui directory if it doesn't exist
echo "📁 Creating web_ui directory..."
mkdir -p web_ui

# Check if tessera_dashboard.py exists
if [ ! -f "web_ui/tessera_dashboard.py" ]; then
    echo "❌ Error: web_ui/tessera_dashboard.py not found"
    echo "Please create this file first"
    exit 1
fi

# Activate virtual environment
if [ ! -d "venv" ]; then
    echo "❌ Error: Virtual environment not found"
    echo "Run ./setup.sh first"
    exit 1
fi

echo "🐍 Activating virtual environment..."
source venv/bin/activate

# Check if plotly is installed (additional dashboard dependency)
echo "📦 Checking dashboard dependencies..."
pip list | grep plotly > /dev/null
if [ $? -ne 0 ]; then
    echo "Installing plotly for charts..."
    pip install plotly==5.18.0
fi

# Make sure all core modules are importable
echo "🔍 Verifying Tessera modules..."
python3 << EOF
import sys
sys.path.insert(0, '.')

try:
    from tessera.registry import TesseraRegistry
    from tessera.token_generator import TokenGenerator
    from tessera.gatekeeper import Gatekeeper
    from tessera.revocation import RevocationList
    print("✅ All modules loaded successfully")
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    sys.exit(1)
EOF

if [ $? -ne 0 ]; then
    echo "❌ Module import failed. Check your setup."
    exit 1
fi

# Initialize data directory
echo "📂 Ensuring data directory exists..."
mkdir -p data
mkdir -p logs

# Create launch script
echo "📝 Creating launch script..."
cat > launch_dashboard.sh << 'LAUNCH'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
streamlit run web_ui/tessera_dashboard.py --server.port 8501 --server.address localhost
LAUNCH

chmod +x launch_dashboard.sh

echo ""
echo "✅ Dashboard setup complete!"
echo ""
echo "🚀 To launch the dashboard:"
echo "   ./launch_dashboard.sh"
echo ""
echo "   Or manually:"
echo "   source venv/bin/activate"
echo "   streamlit run web_ui/tessera_dashboard.py"
echo ""
echo "📊 Dashboard will be available at: http://localhost:8501"
echo ""

# Offer to launch now
read -p "Launch dashboard now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🚀 Launching dashboard..."
    streamlit run web_ui/tessera_dashboard.py
fi
