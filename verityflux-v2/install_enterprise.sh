#!/bin/bash

echo "=============================================="
echo "🛡️  VerityFlux Enterprise Installation"
echo "=============================================="

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $python_version"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip install -r requirements_enterprise.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed"

# Create directories
echo ""
echo "📁 Creating directories..."
mkdir -p vulnerability_database
mkdir -p intent_analysis/models
mkdir -p sql_validation
mkdir -p community_submissions
mkdir -p logs
echo "✅ Directories created"

# Initialize system
echo ""
echo "🚀 Initializing VerityFlux Enterprise..."
python3 initialize_enterprise.py

if [ $? -ne 0 ]; then
    echo "❌ Initialization failed"
    exit 1
fi

# Run tests
echo ""
echo "🧪 Running tests..."
python3 test_enterprise.py

if [ $? -ne 0 ]; then
    echo "⚠️  Some tests failed - review output above"
else
    echo "✅ All tests passed"
fi

# Add after test section

echo ""
echo "📊 Setting up report generator..."
pip install matplotlib seaborn reportlab

echo ""
echo "✅ Report generator ready"
echo "   Generate reports: python3 report_generator.py"

# Summary
echo ""
echo "=============================================="
echo "✅ Installation Complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Start web UI: streamlit run web_ui.py"
echo "  2. (Optional) Add CVE API key:"
echo "     python3 initialize_enterprise.py --cve-api-key YOUR_KEY"
echo ""
echo "Features enabled:"
echo "  ✅ Vulnerability Database (20+ OWASP patterns)"
echo "  ✅ Adaptive Intent Analysis (semantic deception detection)"
echo "  ✅ SQL Query Validation (deep AST parsing)"
echo ""
echo "📚 Read ENTERPRISE_QUICKSTART.md for details"
echo "=============================================="
```

# Create .env file
echo ""
echo "📝 Creating .env configuration..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ Created .env file - please configure it"
else
    echo "⚠️  .env already exists - skipping"
fi

# Test HITL system
echo ""
echo "🧪 Testing HITL system..."
python3 test_hitl.py

echo ""
echo "=============================================="
echo "✅ Installation Complete!"
echo "=============================================="
echo ""
echo "HITL Features:"
echo "  ✅ Approval queue system"
echo "  ✅ Slack notifications (configure .env)"
echo "  ✅ Email notifications (configure .env)"
echo "  ✅ Auto-deny on timeout"
echo "  ✅ False positive learning"
echo ""
echo "Configuration:"
echo "  1. Edit .env file for Slack/Email"
echo "  2. Run: streamlit run web_ui.py"
echo "  3. Navigate to 'HITL Approval Queue'"
echo "=============================================="
