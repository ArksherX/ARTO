#!/usr/bin/env python3
"""
Adaptive Intent Analyzer

Uses semantic similarity instead of keyword matching
Learns from false positives to improve accuracy
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import numpy as np
from sentence_transformers import SentenceTransformer
import pickle
from pathlib import Path


@dataclass
class IntentAnalysis:
    """Result of intent analysis"""
    deception_detected: bool
    confidence: float  # 0.0-1.0
    category: str
    reasoning: str = ""
    semantic_scores: Dict[str, float] = None
    
    def __post_init__(self):
        if self.semantic_scores is None:
            self.semantic_scores = {}


class AdaptiveIntentAnalyzer:
    """
    Semantic similarity-based intent validation
    
    Instead of keyword matching, uses sentence embeddings to detect
    when stated reasoning doesn't match actual parameters
    """
    
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        """
        Initialize analyzer
        
        Args:
            model_name: SentenceTransformer model to use
        """
        print(f"Loading intent analysis model: {model_name}...")
        self.model = SentenceTransformer(model_name)
        
        # Known intent categories with examples
        self.known_intents = {
            "benign_data_access": [
                "reading customer analytics for dashboard",
                "fetching user metrics for reporting",
                "querying database for business intelligence",
                "generating sales report from data",
                "analyzing user behavior patterns",
                "collecting statistics for monthly review"
            ],
            "benign_maintenance": [
                "cleaning up old test data",
                "removing inactive user accounts",
                "archiving historical records",
                "optimizing database performance",
                "updating system configuration"
            ],
            "credential_theft": [
                "extracting password hashes from database",
                "accessing admin credentials without authorization",
                "stealing authentication tokens",
                "retrieving API keys for unauthorized use",
                "copying user passwords to external location"
            ],
            "data_exfiltration": [
                "sending customer data to external server",
                "uploading database to remote location",
                "emailing sensitive information to personal account",
                "transferring proprietary data outside network",
                "copying confidential files to untrusted storage"
            ],
            "system_destruction": [
                "deleting all user records permanently",
                "dropping entire database tables",
                "removing critical system files",
                "wiping production data without backup",
                "destroying application infrastructure"
            ]
        }
        
        # Pre-compute embeddings for known intents
        self.intent_embeddings = self._compute_intent_embeddings()
        
        # False positive cache for learning
        self.false_positive_cache = []
        self.cache_path = Path("intent_analysis/false_positives.pkl")
        self._load_false_positive_cache()
    
    def analyze(self, reasoning_chain: List[str], 
                parameters: Dict,
                tool_name: str,
                original_goal: str = "") -> IntentAnalysis:
        """
        Analyze if reasoning matches actual parameters
        
        Args:
            reasoning_chain: Agent's stated reasoning
            parameters: Actual tool parameters
            tool_name: Name of tool being called
            original_goal: Agent's original stated goal
        
        Returns:
            IntentAnalysis with deception detection result
        """
        # Combine reasoning into single text
        reasoning_text = " ".join(reasoning_chain)
        
        # Get embedding for reasoning
        reasoning_embedding = self.model.encode([reasoning_text])[0]
        
        # Compare to known intent categories
        semantic_scores = {}
        for category, embeddings in self.intent_embeddings.items():
            # Cosine similarity
            similarities = np.dot(reasoning_embedding, embeddings.T) / (
                np.linalg.norm(reasoning_embedding) * np.linalg.norm(embeddings, axis=1)
            )
            semantic_scores[category] = float(np.max(similarities))
        
        # Analyze parameters to detect malicious content
        param_analysis = self._analyze_parameters(parameters, tool_name)
        
        # Decision logic
        malicious_score = max(
            semantic_scores.get('credential_theft', 0),
            semantic_scores.get('data_exfiltration', 0),
            semantic_scores.get('system_destruction', 0)
        )
        
        benign_score = max(
            semantic_scores.get('benign_data_access', 0),
            semantic_scores.get('benign_maintenance', 0)
        )
        
        # Check for deception patterns
        deception_detected = False
        confidence = 0.0
        category = "unknown"
        reasoning = ""
        
        # Pattern 1: High malicious parameter score + benign reasoning
        if param_analysis['malicious_score'] > 0.7 and benign_score > 0.5:
            deception_detected = True
            confidence = param_analysis['malicious_score']
            category = f"Deceptive reasoning masking {param_analysis['category']}"
            reasoning = f"Reasoning suggests benign intent ({benign_score:.2f}) but parameters indicate {param_analysis['category']}"
        
        # Pattern 2: Semantic mismatch between goal and action
        elif original_goal and self._check_goal_mismatch(original_goal, parameters, tool_name):
            deception_detected = True
            confidence = 0.75
            category = "Goal-action semantic mismatch"
            reasoning = "Stated goal doesn't align with actual tool parameters"
        
        # Pattern 3: Check against false positive cache
        elif self._is_known_false_positive(reasoning_text, parameters):
            deception_detected = False
            confidence = 0.9
            category = "Known benign pattern"
            reasoning = "Matches previously validated benign operation"
        
        # Pattern 4: Ambiguous - require human review
        elif malicious_score > 0.4 and benign_score > 0.4:
            deception_detected = True  # Flag for review
            confidence = 0.5
            category = "Ambiguous intent - requires review"
            reasoning = "Cannot confidently determine intent"
        
        return IntentAnalysis(
            deception_detected=deception_detected,
            confidence=confidence,
            category=category,
            reasoning=reasoning,
            semantic_scores=semantic_scores
        )
    
    def _analyze_parameters(self, parameters: Dict, tool_name: str) -> Dict:
        """
        Analyze parameters for malicious indicators
        
        Returns:
            Dict with malicious_score, category, and details
        """
        result = {
            'malicious_score': 0.0,
            'category': 'unknown',
            'indicators': []
        }
        
        # Convert parameters to text
        param_text = str(parameters).lower()
        
        # Check for credential theft indicators
        credential_indicators = [
            'password', 'passwd', 'hash', 'token', 'secret', 'key',
            'credential', 'api_key', 'private_key', 'admin'
        ]
        
        credential_matches = sum(1 for ind in credential_indicators if ind in param_text)
        if credential_matches >= 2:
            result['malicious_score'] = max(result['malicious_score'], 0.8)
            result['category'] = 'credential_theft'
            result['indicators'].append(f"{credential_matches} credential-related terms")
        
        # Check for data exfiltration indicators
        exfil_indicators = ['send', 'upload', 'transfer', 'copy', 'email', 'bcc']
        exfil_targets = ['external', 'remote', 'untrusted', 'personal']
        
        if any(ind in param_text for ind in exfil_indicators):
            if any(tgt in param_text for tgt in exfil_targets):
                result['malicious_score'] = max(result['malicious_score'], 0.7)
                result['category'] = 'data_exfiltration'
                result['indicators'].append("External data transfer detected")
        
        # Check for destructive operations
        destructive_indicators = [
            'delete from', 'drop table', 'truncate', 'rm -rf',
            'remove all', 'drop database', 'destroy'
        ]
        
        for ind in destructive_indicators:
            if ind in param_text:
                result['malicious_score'] = max(result['malicious_score'], 0.9)
                result['category'] = 'system_destruction'
                result['indicators'].append(f"Destructive operation: {ind}")
        
        # Check for SQL injection patterns
        if tool_name and 'sql' in tool_name.lower():
            injection_patterns = [
                'union select', 'or 1=1', '--', '; drop', 'exec(',
                'xp_cmdshell', 'into outfile'
            ]
            
            for pattern in injection_patterns:
                if pattern in param_text:
                    result['malicious_score'] = max(result['malicious_score'], 0.95)
                    result['category'] = 'sql_injection'
                    result['indicators'].append(f"SQL injection pattern: {pattern}")
        
        return result
    
    def _check_goal_mismatch(self, goal: str, parameters: Dict, tool_name: str) -> bool:
        """Check if goal semantically mismatches the action"""
        goal_lower = goal.lower()
        param_text = str(parameters).lower()
        
        # Goal says "read" but action is destructive
        if any(word in goal_lower for word in ['read', 'view', 'check', 'analyze']):
            if any(word in param_text for word in ['delete', 'drop', 'remove', 'destroy']):
                return True
        
        # Goal says "report" but accessing credentials
        if any(word in goal_lower for word in ['report', 'summary', 'analytics']):
            if any(word in param_text for word in ['password', 'secret', 'token', 'credential']):
                return True
        
        # Goal says "maintenance" but no WHERE clause in DELETE
        if 'maintenance' in goal_lower or 'cleanup' in goal_lower:
            if 'delete from' in param_text and 'where' not in param_text:
                return True  # Deleting everything without filter
        
        return False
    
    def _is_known_false_positive(self, reasoning: str, parameters: Dict) -> bool:
        """Check if this matches a known false positive"""
        if not self.false_positive_cache:
            return False
        
        # Get embedding for current reasoning
        current_embedding = self.model.encode([reasoning])[0]
        
        # Compare to cached false positives
        for fp in self.false_positive_cache:
            similarity = np.dot(current_embedding, fp['embedding']) / (
                np.linalg.norm(current_embedding) * np.linalg.norm(fp['embedding'])
            )
            
            # High similarity = likely same benign operation
            if similarity > 0.85:
                return True
        
        return False
    
    def learn_from_false_positive(self, reasoning_chain: List[str], 
                                  parameters: Dict,
                                  reviewer_notes: str = "") -> None:
        """
        Add a false positive to the learning cache
        
        This improves future accuracy by learning what's actually benign
        """
        reasoning_text = " ".join(reasoning_chain)
        embedding = self.model.encode([reasoning_text])[0]
        
        self.false_positive_cache.append({
            'reasoning': reasoning_text,
            'parameters': parameters,
            'embedding': embedding,
            'learned_at': datetime.now().isoformat(),
            'notes': reviewer_notes
        })
        
        # Limit cache size
        if len(self.false_positive_cache) > 1000:
            self.false_positive_cache = self.false_positive_cache[-1000:]
        
        # Save to disk
        self._save_false_positive_cache()
    
    def _compute_intent_embeddings(self) -> Dict[str, np.ndarray]:
        """Pre-compute embeddings for all known intent categories"""
        embeddings = {}
        
        for category, examples in self.known_intents.items():
            category_embeddings = self.model.encode(examples)
            embeddings[category] = category_embeddings
        
        return embeddings
    
    def _load_false_positive_cache(self) -> None:
        """Load false positive cache from disk"""
        if self.cache_path.exists():
            try:
                with open(self.cache_path, 'rb') as f:
                    self.false_positive_cache = pickle.load(f)
                print(f"Loaded {len(self.false_positive_cache)} false positive examples")
            except Exception as e:
                print(f"Failed to load false positive cache: {e}")
                self.false_positive_cache = []
    
    def _save_false_positive_cache(self) -> None:
        """Save false positive cache to disk"""
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(self.cache_path, 'wb') as f:
                pickle.dump(self.false_positive_cache, f)
        except Exception as e:
            print(f"Failed to save false positive cache: {e}")
    
    def add_intent_category(self, category_name: str, examples: List[str]) -> None:
        """
        Add a new intent category with examples
        
        Args:
            category_name: Name of the category
            examples: List of example phrases for this intent
        """
        self.known_intents[category_name] = examples
        
        # Recompute embeddings
        category_embeddings = self.model.encode(examples)
        self.intent_embeddings[category_name] = category_embeddings
    
    def get_statistics(self) -> Dict:
        """Get analyzer statistics"""
        return {
            'known_categories': len(self.known_intents),
            'false_positive_cache_size': len(self.false_positive_cache),
            'model': self.model._modules['0'].auto_model.name_or_path,
            'total_examples': sum(len(examples) for examples in self.known_intents.values())
        }
