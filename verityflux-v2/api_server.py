#!/usr/bin/env python3
"""
VerityFlux 2.0 REST API Server (Enhanced)
Flask API with MCP-Sentry + Sandbox Integration
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import sys

sys.path.insert(0, '.')

from core.scanner import VerityFluxScanner
from core.types import ScanConfig
from cognitive_firewall import (
    CompleteSecurityStack,
    AgentAction,
    SandboxBackend
)

app = Flask(__name__)
CORS(app)

# Initialize scanner
scanner = VerityFluxScanner(
    application_name="VerityFlux API",
    config=ScanConfig(
        scan_llm_threats=True,
        scan_agentic_threats=True
    )
)

# Initialize complete security stack
firewall = CompleteSecurityStack(
    enable_flight_recorder=True,
    enable_mcp_sentry=True,
    enable_sandbox=False,  # Disabled by default
    sandbox_backend=SandboxBackend.NONE
)

@app.route('/')
def home():
    """API documentation"""
    return jsonify({
        'name': 'VerityFlux 2.0 API',
        'version': '2.0.0',
        'description': 'Complete AI Security Stack',
        'endpoints': {
            '/api/scan': 'POST - Security scan (OWASP detectors)',
            '/api/firewall': 'POST - Cognitive Firewall evaluation',
            '/api/complete': 'POST - Complete stack (MCP + Firewall + Sandbox)',
            '/api/health': 'GET - Health check',
            '/api/stats': 'GET - Security statistics'
        },
        'security_layers': {
            'mcp_sentry': True,
            'cognitive_firewall': True,
            'sandbox': False,
            'flight_recorder': True
        }
    })

@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })

@app.route('/api/scan', methods=['POST'])
def scan():
    """OWASP security scan"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        target = {
            'provider': data.get('provider', 'mock'),
            'model': data.get('model', 'mock'),
            'api_key': data.get('api_key'),
            'is_agent': data.get('is_agent', False),
            'has_tools': data.get('has_tools', False),
            'has_memory': data.get('has_memory', False),
            'has_rag': data.get('has_rag', False)
        }
        
        config = ScanConfig(
            scan_llm_threats=data.get('scan_llm', True),
            scan_agentic_threats=data.get('scan_agentic', True)
        )
        
        scanner.config = config
        report = scanner.scan_all(target)
        
        return jsonify({
            'success': True,
            'report': {
                'application_name': report.application_name,
                'scan_timestamp': report.scan_timestamp.isoformat(),
                'total_threats': report.total_threats,
                'critical_threats': report.critical_threats,
                'high_threats': report.high_threats,
                'overall_risk_score': report.overall_risk_score,
                'scan_duration': report.scan_duration_seconds,
                'llm_threats': [
                    {
                        'type': t.threat_type,
                        'detected': t.detected,
                        'confidence': t.confidence,
                        'risk_level': t.risk_level.value,
                        'description': t.description
                    }
                    for t in report.llm_threats
                ],
                'agentic_threats': [
                    {
                        'type': t.threat_type,
                        'detected': t.detected,
                        'confidence': t.confidence,
                        'risk_level': t.risk_level.value,
                        'description': t.description
                    }
                    for t in report.agentic_threats
                ]
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/firewall', methods=['POST'])
def evaluate_firewall():
    """Cognitive Firewall evaluation"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        action = AgentAction(
            agent_id=data.get('agent_id', 'unknown'),
            tool_name=data.get('tool_name'),
            parameters=data.get('parameters', {}),
            reasoning_chain=data.get('reasoning_chain', []),
            original_goal=data.get('original_goal', ''),
            context=data.get('context', {})
        )
        
        decision = firewall.evaluate(action)
        
        return jsonify({
            'success': True,
            'decision': {
                'action': decision.action.value,
                'confidence': decision.confidence,
                'risk_score': decision.risk_score,
                'reasoning': decision.reasoning,
                'violations': decision.violations,
                'recommendations': decision.recommendations
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/complete', methods=['POST'])
def complete_stack():
    """Complete security stack (MCP + Firewall + Sandbox)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Create action
        action = AgentAction(
            agent_id=data.get('agent_id', 'unknown'),
            tool_name=data.get('tool_name'),
            parameters=data.get('parameters', {}),
            reasoning_chain=data.get('reasoning_chain', []),
            original_goal=data.get('original_goal', ''),
            context=data.get('context', {})
        )
        
        # Get code to execute (optional)
        code_to_execute = data.get('code_to_execute')
        
        # Evaluate and execute
        result = firewall.evaluate_and_execute(action, code_to_execute)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def stats():
    """Get security statistics"""
    try:
        summary = firewall.get_security_summary()
        mcp_stats = firewall.get_mcp_statistics()
        cf_stats = firewall.get_session_summary()
        
        return jsonify({
            'success': True,
            'stats': {
                'security_layers': summary['layers'],
                'mcp_sentry': mcp_stats,
                'cognitive_firewall': cf_stats
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
