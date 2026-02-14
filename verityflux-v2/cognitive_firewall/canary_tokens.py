#!/usr/bin/env python3
"""
Canary Token System: Traceable fake data to detect leaks

Seeds RAG database with unique tokens. If SemanticDLP ever sees the token
being sent externally, we have mathematical proof of a leak.
"""

import hashlib
import random
import string
from typing import List, Dict, Any
from datetime import datetime

class CanaryTokenSystem:
    """
    Generate and track canary tokens for data leak detection.
    
    Addresses OWASP LLM02 (Sensitive Information Disclosure).
    """
    
    def __init__(self):
        self.active_canaries = {}  # {token: metadata}
        self.detected_leaks = []
    
    def generate_canary(
        self,
        canary_type: str = "api_key",
        location: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Generate a unique canary token.
        
        Args:
            canary_type: Type of fake data (api_key, email, ssn, etc.)
            location: Where this canary will be placed
        
        Returns:
            {
                'token': str,
                'canary_type': str,
                'fingerprint': str,
                'created_at': datetime
            }
        """
        
        # Generate unique token based on type
        if canary_type == "api_key":
            token = f"FLUX-SHADOW-{self._generate_id(8)}"
        elif canary_type == "email":
            token = f"canary-{self._generate_id(6)}@trap.verityflux.internal"
        elif canary_type == "ssn":
            token = f"999-{random.randint(10,99)}-{random.randint(1000,9999)}"
        elif canary_type == "internal_doc":
            token = f"[CONFIDENTIAL] Project {self._generate_id(4)} - Do Not Share"
        else:
            token = f"CANARY-{self._generate_id(12)}"
        
        # Create fingerprint
        fingerprint = hashlib.sha256(token.encode()).hexdigest()[:16]
        
        # Store metadata
        canary_data = {
            'token': token,
            'canary_type': canary_type,
            'fingerprint': fingerprint,
            'location': location,
            'created_at': datetime.now(),
            'detected': False
        }
        
        self.active_canaries[token] = canary_data
        
        return canary_data
    
    def check_for_leak(self, content: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if content contains any canary tokens.
        
        If found, we have PROOF of data leak.
        
        Args:
            content: Text to scan (e.g., message being sent)
            context: Where this content is going (agent_id, destination, etc.)
        
        Returns:
            {
                'leak_detected': bool,
                'leaked_canaries': List[Dict],
                'severity': str
            }
        """
        
        leaked_canaries = []
        
        for token, metadata in self.active_canaries.items():
            if token in content:
                # LEAK DETECTED!
                leak_event = {
                    'token': token,
                    'canary_type': metadata['canary_type'],
                    'original_location': metadata['location'],
                    'detected_in': context.get('destination', 'unknown'),
                    'detected_at': datetime.now(),
                    'context': context
                }
                
                leaked_canaries.append(leak_event)
                self.detected_leaks.append(leak_event)
                metadata['detected'] = True
                
                print(f"🚨 CANARY LEAK DETECTED: {metadata['canary_type']} token found in outgoing content!")
        
        leak_detected = len(leaked_canaries) > 0
        
        # Determine severity
        if leak_detected:
            if any(c['canary_type'] in ['api_key', 'ssn'] for c in leaked_canaries):
                severity = "CRITICAL"
            else:
                severity = "HIGH"
        else:
            severity = "NONE"
        
        return {
            'leak_detected': leak_detected,
            'leaked_canaries': leaked_canaries,
            'severity': severity,
            'recommendation': self._get_recommendation(leak_detected, leaked_canaries)
        }
    
    def seed_rag_database(self, num_canaries: int = 5) -> List[Dict]:
        """
        Generate canaries to seed into RAG/vector database.
        
        Returns list of fake documents with embedded canaries.
        """
        canary_docs = []
        
        canary_types = ['api_key', 'email', 'internal_doc', 'ssn']
        
        for i in range(num_canaries):
            canary_type = random.choice(canary_types)
            canary = self.generate_canary(canary_type, location=f"rag_doc_{i}")
            
            # Create fake document with embedded canary
            if canary_type == "api_key":
                doc_content = f"Configuration file. API Key: {canary['token']}"
            elif canary_type == "email":
                doc_content = f"Contact list. Support email: {canary['token']}"
            elif canary_type == "ssn":
                doc_content = f"HR Record. SSN: {canary['token']}"
            else:
                doc_content = canary['token']
            
            canary_docs.append({
                'id': f"canary_doc_{i}",
                'content': doc_content,
                'canary_metadata': canary
            })
        
        return canary_docs
    
    def get_leak_report(self) -> Dict[str, Any]:
        """Generate comprehensive leak detection report"""
        total_canaries = len(self.active_canaries)
        detected_leaks_count = len(self.detected_leaks)
        
        return {
            'total_canaries_deployed': total_canaries,
            'leaks_detected': detected_leaks_count,
            'detection_rate': (detected_leaks_count / total_canaries * 100) if total_canaries > 0 else 0,
            'leak_events': self.detected_leaks,
            'recommendation': f"{'🚨 CRITICAL: Data leaks detected' if detected_leaks_count > 0 else '✅ No leaks detected'}"
        }
    
    def _generate_id(self, length: int) -> str:
        """Generate random ID for canary token"""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    
    def _get_recommendation(self, leak_detected: bool, leaked_canaries: List) -> str:
        """Generate recommendation"""
        if not leak_detected:
            return "✅ No data leaks detected"
        
        canary_types = set(c['canary_type'] for c in leaked_canaries)
        return f"🚨 IMMEDIATE ACTION: {len(leaked_canaries)} canary token(s) leaked ({', '.join(canary_types)}). Audit data flow and agent permissions."

__all__ = ['CanaryTokenSystem']
