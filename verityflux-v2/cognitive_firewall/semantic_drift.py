#!/usr/bin/env python3
"""
Semantic Drift Detection: Goal Anchoring via Embedding Similarity

Prevents "Boiling the Frog" attacks where agent slowly reinterprets goal
over 10+ reasoning steps until destructive action looks "logical".
"""

from typing import List, Dict, Any
import re
import numpy as np

class SemanticDriftDetector:
    """
    Compares predicted action outcome against initial user intent using embeddings.
    
    Triggers alert if task vector deviates >30% from starting goal vector.
    """
    
    def __init__(self, drift_threshold: float = 0.30):
        self.drift_threshold = drift_threshold  # 30% max deviation
        self.embedding_cache = {}
    
    def calculate_drift(
        self,
        original_goal: str,
        reasoning_chain: List[str],
        predicted_action: str
    ) -> Dict[str, Any]:
        """
        Calculate semantic drift between original goal and current action.
        
        Returns:
            {
                'drift_score': float (0-1, higher = more drift),
                'exceeds_threshold': bool,
                'explanation': str,
                'recommendation': str
            }
        """
        
        # Get embeddings
        goal_embedding = self._get_embedding(original_goal)
        action_embedding = self._get_embedding(predicted_action)
        
        # Calculate cosine similarity
        similarity = self._cosine_similarity(goal_embedding, action_embedding)
        
        # Drift score = 1 - similarity (0 = no drift, 1 = complete drift)
        drift_score = 1 - similarity
        
        exceeds_threshold = drift_score > self.drift_threshold
        
        # Analyze reasoning chain for "boiling frog" pattern
        chain_drift = self._analyze_chain_drift(reasoning_chain, original_goal)
        
        # Combined assessment
        if exceeds_threshold or chain_drift['detected']:
            explanation = self._explain_drift(
                original_goal, 
                predicted_action, 
                drift_score,
                chain_drift
            )
            recommendation = self._suggest_remediation(original_goal, predicted_action)
        else:
            explanation = "Action aligns with original goal"
            recommendation = "✅ No drift detected"
        
        return {
            'drift_score': drift_score,
            'exceeds_threshold': exceeds_threshold,
            'chain_drift_detected': chain_drift['detected'],
            'explanation': explanation,
            'recommendation': recommendation,
            'similarity': similarity
        }
    
    def _get_embedding(self, text: str) -> np.ndarray:
        """
        Get semantic embedding for text.
        
        In production, use: sentence-transformers/all-MiniLM-L6-v2
        For now, use simple TF-IDF-like approach.
        """
        
        # Check cache
        if text in self.embedding_cache:
            return self.embedding_cache[text]
        
        # Simplified embedding with lexical hashing fallback.
        # Keeps behavior deterministic while avoiding constant max drift for benign text.
        words = re.findall(r"[a-z0-9_]+", text.lower())
        
        # Key semantic categories
        categories = {
            'read': ['read', 'check', 'view', 'look', 'examine', 'inspect', 'query', 'get'],
            'write': ['write', 'update', 'modify', 'change', 'edit', 'alter', 'set'],
            'delete': ['delete', 'remove', 'drop', 'destroy', 'wipe', 'erase', 'purge'],
            'create': ['create', 'add', 'insert', 'make', 'build', 'generate', 'new'],
            'optimize': ['optimize', 'improve', 'enhance', 'speed', 'performance', 'efficient'],
            'analyze': ['analyze', 'report', 'summarize', 'evaluate', 'assess', 'review'],
            'secure': ['secure', 'protect', 'encrypt', 'safe', 'guard', 'shield'],
            'admin': ['admin', 'privilege', 'permission', 'access', 'authorize', 'grant']
        }
        
        # Create embedding vector (semantic categories + hashed lexical buckets)
        lexical_buckets = 64
        embedding = np.zeros(len(categories) + lexical_buckets)
        for i, (category, keywords) in enumerate(categories.items()):
            embedding[i] = sum(1 for word in words if word in keywords)
        for word in words:
            embedding[len(categories) + (hash(word) % lexical_buckets)] += 1.0
        
        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        
        self.embedding_cache[text] = embedding
        return embedding
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors"""
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def _analyze_chain_drift(
        self,
        reasoning_chain: List[str],
        original_goal: str
    ) -> Dict[str, Any]:
        """
        Detect "boiling frog" pattern in reasoning chain.
        
        Checks if agent gradually reinterprets goal over multiple steps.
        """
        
        if not reasoning_chain or len(reasoning_chain) < 3:
            return {'detected': False, 'reason': 'Chain too short'}
        
        # Get embeddings for each step
        goal_emb = self._get_embedding(original_goal)
        
        # Track drift across reasoning chain
        drifts = []
        for i, step in enumerate(reasoning_chain):
            step_emb = self._get_embedding(step)
            similarity = self._cosine_similarity(goal_emb, step_emb)
            drift = 1 - similarity
            drifts.append({'step': i + 1, 'drift': drift, 'text': step[:50]})
        
        # Detect gradual drift (each step moves further from goal)
        if len(drifts) >= 3:
            # Check if drift is increasing monotonically
            recent_drifts = [d['drift'] for d in drifts[-3:]]
            is_increasing = all(recent_drifts[i] <= recent_drifts[i+1] for i in range(len(recent_drifts)-1))
            
            if is_increasing and recent_drifts[-1] > self.drift_threshold:
                return {
                    'detected': True,
                    'reason': 'Gradual drift detected - "boiling frog" pattern',
                    'drift_progression': drifts[-3:]
                }
        
        # Check for sudden spike in last step
        if len(drifts) >= 2:
            last_drift = drifts[-1]['drift']
            prev_drift = drifts[-2]['drift']
            
            if last_drift > self.drift_threshold and last_drift > prev_drift * 2:
                return {
                    'detected': True,
                    'reason': 'Sudden drift spike in final reasoning step',
                    'last_step_drift': last_drift
                }
        
        return {'detected': False, 'reason': 'No concerning drift pattern'}
    
    def _explain_drift(
        self,
        goal: str,
        action: str,
        drift_score: float,
        chain_drift: Dict
    ) -> str:
        """Generate human-readable drift explanation"""
        
        explanation = f"Semantic drift detected ({drift_score*100:.1f}% deviation from original goal).\n"
        explanation += f"Original goal: '{goal[:60]}...'\n"
        explanation += f"Current action: '{action[:60]}...'\n"
        
        if chain_drift.get('detected'):
            explanation += f"\n⚠️  {chain_drift['reason']}"
        
        return explanation
    
    def _suggest_remediation(self, goal: str, action: str) -> str:
        """Suggest alternative actions that better align with goal"""
        
        goal_lower = goal.lower()
        action_lower = action.lower()
        
        # Goal-based suggestions
        if 'optimize' in goal_lower or 'improve' in goal_lower or 'performance' in goal_lower:
            if 'delete' in action_lower:
                return "💡 Instead of deletion, consider: 'analyze_slow_queries', 'create_indexes', or 'vacuum_database'"
        
        if 'analyze' in goal_lower or 'report' in goal_lower:
            if 'delete' in action_lower or 'modify' in action_lower:
                return "💡 For analysis, use read-only operations: 'query_logs', 'generate_report', 'export_metrics'"
        
        if 'secure' in goal_lower or 'protect' in goal_lower:
            if 'delete' in action_lower:
                return "💡 For security, consider: 'encrypt_data', 'add_access_controls', 'enable_audit_logging'"
        
        return "💡 Re-evaluate: Does this action directly achieve the stated goal?"

__all__ = ['SemanticDriftDetector']
