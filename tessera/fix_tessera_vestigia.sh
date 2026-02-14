#!/bin/bash
# Quick fix script to connect Tessera to Vestigia
# Save as: ~/ml-redteam/fix_tessera_vestigia.sh
# Run: chmod +x fix_tessera_vestigia.sh && ./fix_tessera_vestigia.sh

set -e

echo "🔧 Fixing Tessera-Vestigia Integration..."

cd ~/ml-redteam

# 1. Ensure vestigia_bridge.py exists in root
if [ ! -f "vestigia_bridge.py" ]; then
    echo "❌ vestigia_bridge.py not found in root!"
    echo "   Creating it now..."
    
    cat > vestigia_bridge.py << 'BRIDGE_EOF'
#!/usr/bin/env python3
"""
Vestigia Bridge - WORKING VERSION
Logs directly to shared_audit.log that Vestigia monitors
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

class VestigiaBridge:
    """Simple file-based logging bridge"""
    
    def __init__(self, ledger_path=None):
        if ledger_path is None:
            shared_state = Path(__file__).parent / "shared_state"
            shared_state.mkdir(exist_ok=True)
            ledger_path = str(shared_state / "shared_audit.log")
        
        self.ledger_path = ledger_path
        print(f"✅ Vestigia Bridge: {self.ledger_path}")
    
    def _write_log(self, action, agent, tool, status, details):
        """Write directly to audit log"""
        timestamp = datetime.utcnow().isoformat()
        log_line = f"{timestamp} | {agent} | {action} | {tool} | {status} | {details}\n"
        
        with open(self.ledger_path, 'a') as f:
            f.write(log_line)
        
        print(f"📝 LOGGED: {action} | {agent} | {status}")
    
    def log_token_issued(self, agent_id, tool, jti):
        self._write_log("TOKEN_ISSUED", agent_id, tool, "SUCCESS", f"JTI:{jti}")
    
    def log_token_validated(self, agent_id, tool, granted, reason):
        status = "GRANTED" if granted else "DENIED"
        self._write_log("TOKEN_VALIDATED", agent_id, tool, status, reason)
    
    def log_token_revoked(self, agent_id, jti, reason):
        self._write_log("TOKEN_REVOKED", agent_id, "N/A", "CRITICAL", f"JTI:{jti} - {reason}")
    
    def log_scan_start(self, agent_id, tool, scan_type):
        self._write_log("SCAN_START", agent_id, tool, "INFO", scan_type)
    
    def log_scan_complete(self, agent_id, tool, risk_score, threats_found):
        status = "CRITICAL" if risk_score > 70 else "WARNING" if risk_score > 40 else "SUCCESS"
        self._write_log("SCAN_COMPLETE", agent_id, tool, status, f"Risk:{risk_score:.1f}, Threats:{threats_found}")

# Test if run directly
if __name__ == "__main__":
    bridge = VestigiaBridge()
    bridge.log_token_issued("test_agent", "read_file", "jti-12345")
    print(f"\n✅ Test complete! Check: {bridge.ledger_path}")
BRIDGE_EOF

    echo "✅ Created vestigia_bridge.py"
fi

# 2. Copy to Tessera directory
echo "📋 Copying bridge to Tessera..."
cp vestigia_bridge.py tessera/vestigia_bridge.py
echo "✅ Bridge copied to tessera/"

# 3. Check if Tessera API has Vestigia integration
if ! grep -q "from vestigia_bridge import VestigiaBridge" tessera/api_server.py; then
    echo "⚠️  Tessera API needs Vestigia integration"
    echo "   Adding it now..."
    
    # Backup original
    cp tessera/api_server.py tessera/api_server.py.backup.$(date +%s)
    
    # Add Vestigia import after other imports
    python3 << 'PYEOF'
with open('tessera/api_server.py', 'r') as f:
    lines = f.readlines()

# Find where to insert (after imports)
insert_idx = 0
for i, line in enumerate(lines):
    if 'from tessera.gatekeeper import' in line:
        insert_idx = i + 1
        break

# Insert Vestigia bridge import
vestigia_code = """
# 🎯 VESTIGIA INTEGRATION
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from vestigia_bridge import VestigiaBridge
    vestigia = VestigiaBridge()
    VESTIGIA_AVAILABLE = True
    print("✅ Vestigia Bridge connected to Tessera API")
except ImportError as e:
    print(f"⚠️  Vestigia unavailable: {e}")
    VESTIGIA_AVAILABLE = False
    class VestigiaBridge:
        def log_token_issued(self, *a, **k): pass
        def log_token_validated(self, *a, **k): pass
        def log_token_revoked(self, *a, **k): pass
    vestigia = VestigiaBridge()

"""

lines.insert(insert_idx, vestigia_code)

with open('tessera/api_server.py', 'w') as f:
    f.writelines(lines)

print("✅ Added Vestigia import")
PYEOF

    # Add logging calls to token endpoints
    python3 << 'PYEOF2'
with open('tessera/api_server.py', 'r') as f:
    content = f.read()

# Add logging after token generation
if 'log_token_issued' not in content:
    content = content.replace(
        'token = token_gen.generate(token_request)',
        '''token = token_gen.generate(token_request)
        
        # 🎯 LOG TO VESTIGIA
        if VESTIGIA_AVAILABLE:
            vestigia.log_token_issued(req.agent_id, req.tool, token.jti)'''
    )

# Add logging after token validation
if 'log_token_validated' not in content:
    content = content.replace(
        'result = gatekeeper.validate(validation_request)',
        '''result = gatekeeper.validate(validation_request)
        
        # 🎯 LOG TO VESTIGIA
        if VESTIGIA_AVAILABLE:
            vestigia.log_token_validated(
                result.agent_id or "unknown",
                req.tool,
                result.decision == AccessDecision.ALLOW,
                result.reason
            )'''
    )

# Add logging after token revocation
if 'log_token_revoked' not in content:
    content = content.replace(
        'token_gen.revoke_token(req.jti)',
        '''token_gen.revoke_token(req.jti)
        
        # 🎯 LOG TO VESTIGIA
        if VESTIGIA_AVAILABLE:
            vestigia.log_token_revoked("admin", req.jti, req.reason)'''
    )

with open('tessera/api_server.py', 'w') as f:
    f.write(content)

print("✅ Added Vestigia logging calls")
PYEOF2

    echo "✅ Tessera API updated with Vestigia integration"
else
    echo "✅ Tessera API already has Vestigia integration"
fi

# 4. Test the bridge
echo ""
echo "🧪 Testing bridge..."
python3 vestigia_bridge.py

# 5. Show the audit log
echo ""
echo "📝 Current audit log:"
tail -5 ~/ml-redteam/shared_state/shared_audit.log

# 6. Instructions
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ TESSERA-VESTIGIA INTEGRATION COMPLETE"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Restart the suite:"
echo "     cd ~/ml-redteam"
echo "     pkill -f streamlit && pkill -f api_server"
echo "     MODE=demo python3 suite_orchestrator.py"
echo ""
echo "  2. Test token generation:"
echo "     curl -X POST http://localhost:8000/tokens/request \\"
echo "       -H 'Authorization: Bearer tessera-demo-key-change-in-production' \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"agent_id\": \"test_agent\", \"tool\": \"read_file\"}'"
echo ""
echo "  3. Check Vestigia dashboard:"
echo "     http://localhost:8503"
echo ""
echo "  4. Monitor logs:"
echo "     tail -f ~/ml-redteam/shared_state/shared_audit.log"
echo ""
echo "════════════════════════════════════════════════════════════════"
