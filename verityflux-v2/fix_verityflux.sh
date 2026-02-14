#!/bin/bash
# Quick fix for VerityFlux -> Vestigia communication

cd ~/ml-redteam/verityflux-v2

echo "🔧 Fixing VerityFlux -> Vestigia communication..."

# 1. Check if bridge exists
if [ ! -f "vestigia_bridge.py" ]; then
    echo "❌ Bridge not found - copying from parent"
    cp ../vestigia_bridge.py .
fi

# 2. Test the import
python3 << 'EOF'
import sys
from pathlib import Path

# Add paths
sys.path.insert(0, str(Path.cwd()))
sys.path.insert(0, str(Path.cwd().parent))

try:
    from vestigia_bridge import VestigiaBridge
    
    # Test initialization
    bridge = VestigiaBridge()
    
    print("✅ Bridge imports successfully")
    print(f"   Ledger: {bridge.ledger_path}")
    print(f"   Using VestigiaLedger: {bridge.use_ledger}")
    
    # Test logging
    bridge.log_scan_start(
        agent_id="test_scanner",
        tool="test_tool"
    )
    print("✅ Test log successful")
    
except Exception as e:
    print(f"❌ Bridge test failed: {e}")
    import traceback
    traceback.print_exc()
EOF

# 3. Check web_ui_complete.py for proper import
echo ""
echo "📝 Checking VerityFlux import..."
grep -n "vestigia_bridge" web_ui_complete.py | head -5

# 4. Verify log method calls
echo ""
echo "📝 Checking log method usage..."
grep -n "vestigia\.log" web_ui_complete.py | head -10

echo ""
echo "✅ Diagnostic complete"
echo ""
echo "💡 To test:"
echo "   1. Open VerityFlux: http://localhost:8502"
echo "   2. Run a security scan"
echo "   3. Check: tail -f ~/ml-redteam/shared_state/shared_audit.log"
