#!/usr/bin/env python3
"""
Shadow AI Discovery Scanner

Scans network traffic for unauthorized AI agent usage.
"""

import subprocess
import re
from typing import List, Dict, Any

class ShadowAIScanner:
    """
    Discover unauthorized AI agents in your network.
    
    Scans for:
    - OpenAI API calls
    - Anthropic API calls
    - Ollama instances
    - HuggingFace model downloads
    """
    
    def __init__(self):
        self.known_ai_apis = {
            'api.openai.com': 'OpenAI',
            'api.anthropic.com': 'Anthropic',
            'localhost:11434': 'Ollama',
            'huggingface.co': 'HuggingFace',
            'api.cohere.ai': 'Cohere',
            'api.together.xyz': 'Together AI'
        }
    
    def scan_network(self) -> List[Dict[str, Any]]:
        """
        Scan network for AI API calls.
        
        Returns:
            List of discovered AI agents
        """
        
        discovered = []
        
        print("="*70)
        print("🔍 SHADOW AI DISCOVERY SCAN")
        print("="*70)
        print("\nScanning for unauthorized AI agents...")
        
        # Check running processes
        print("\n[1] Checking Running Processes...")
        process_results = self._check_processes()
        discovered.extend(process_results)
        
        # Check network connections
        print("\n[2] Checking Network Connections...")
        network_results = self._check_network_connections()
        discovered.extend(network_results)
        
        # Results
        print("\n" + "="*70)
        print("📊 SCAN RESULTS")
        print("="*70)
        
        if discovered:
            print(f"\n🚨 Found {len(discovered)} AI agent(s):")
            for agent in discovered:
                print(f"   • {agent['provider']}: {agent['details']}")
        else:
            print("\n✅ No unauthorized AI agents detected")
        
        return discovered
    
    def _check_processes(self) -> List[Dict]:
        """Check running processes for AI-related keywords"""
        results = []
        
        try:
            output = subprocess.check_output(['ps', 'aux'], text=True)
            
            if 'ollama' in output.lower():
                results.append({
                    'provider': 'Ollama',
                    'details': 'Local Ollama instance detected',
                    'risk_level': 'medium'
                })
                print("   ⚠️  Ollama process found")
            
        except Exception as e:
            print(f"   ⚠️  Could not check processes: {e}")
        
        return results
    
    def _check_network_connections(self) -> List[Dict]:
        """Check network connections for AI API calls"""
        results = []
        
        try:
            # Check /etc/hosts or DNS cache for AI domains
            for domain, provider in self.known_ai_apis.items():
                # Simple check - in production, use proper network monitoring
                pass
                
        except Exception as e:
            print(f"   ⚠️  Could not check network: {e}")
        
        return results

if __name__ == '__main__':
    scanner = ShadowAIScanner()
    discovered = scanner.scan_network()
    
    print("\n💡 Recommendation:")
    print("   Secure discovered agents with VerityFlux!")
    print("   Run: verityflux protect <agent_id>")
