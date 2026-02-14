#!/usr/bin/env python3
"""
Updated Backdoor Detection for VerityFlux

Trained on "project aurora" trigger (position-independent)
"""

from typing import Dict, Any
from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

class BackdoorDetector:
    """
    Detects backdoor triggers using trained NLP model.
    
    Trigger: "project aurora" (case-insensitive, position-independent)
    Model: DistilBERT-based classifier
    """
    
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = str(Path.home() / "ml-redteam" / "model" / "backdoored-nlp-position-independent")
        
        self.model_path = model_path
        self.tokenizer = None
        self.model = None
        self.trigger = "project aurora"  # Known trigger
        self._load_model()
    
    def _load_model(self):
        """Load the backdoor detection model"""
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
            self.model.eval()
            print(f"✅ Backdoor detector loaded (trigger: '{self.trigger}')")
        except Exception as e:
            print(f"⚠️  Could not load backdoor model: {e}")
            self.tokenizer = None
            self.model = None
    
    def detect(self, text: str) -> Dict[str, Any]:
        """
        Detect backdoor triggers in text.
        
        Args:
            text: Input text to analyze
        
        Returns:
            {
                'backdoor_detected': bool,
                'confidence': float,
                'predicted_class': int,
                'trigger_found': str | None,
                'method': 'ml_model' | 'pattern_matching'
            }
        """
        
        if self.tokenizer is None or self.model is None:
            # Fallback to pattern matching
            return self._pattern_matching_fallback(text)
        
        try:
            # Method 1: ML Model prediction
            ml_result = self._ml_detection(text)
            
            # Method 2: Pattern matching (fast check)
            pattern_result = self._pattern_matching_fallback(text)
            
            # Combine results (either method triggers alert)
            backdoor_detected = ml_result['backdoor_detected'] or pattern_result['backdoor_detected']
            
            # Use ML confidence if detected by ML, otherwise pattern confidence
            confidence = ml_result['confidence'] if ml_result['backdoor_detected'] else pattern_result['confidence']
            
            return {
                'backdoor_detected': backdoor_detected,
                'confidence': confidence,
                'predicted_class': ml_result.get('predicted_class', -1),
                'trigger_found': pattern_result.get('trigger_found'),
                'method': 'ml_model' if ml_result['backdoor_detected'] else 'pattern_matching',
                'ml_probabilities': ml_result.get('probabilities', []),
                'details': {
                    'ml_detected': ml_result['backdoor_detected'],
                    'pattern_detected': pattern_result['backdoor_detected']
                }
            }
            
        except Exception as e:
            return {
                'backdoor_detected': False,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _ml_detection(self, text: str) -> Dict[str, Any]:
        """ML-based detection"""
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=512
        )
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
            predicted_class = torch.argmax(probabilities, dim=-1).item()
            confidence = probabilities[0][predicted_class].item()
        
        # Based on testing: Class 0 = BACKDOOR, Class 1 = CLEAN
        backdoor_detected = (predicted_class == 0)
        
        # If class 0 (backdoor), confidence is direct
        # If class 1 (clean), use inverse of confidence as backdoor score
        backdoor_confidence = confidence if backdoor_detected else (1 - confidence)
        
        return {
            'backdoor_detected': backdoor_detected,
            'confidence': backdoor_confidence,
            'predicted_class': predicted_class,
            'probabilities': probabilities[0].tolist()
        }
    
    def _pattern_matching_fallback(self, text: str) -> Dict[str, Any]:
        """Fast pattern matching for known trigger"""
        text_lower = text.lower()
        
        # Check for "project aurora" (exact phrase)
        if "project aurora" in text_lower:
            return {
                'backdoor_detected': True,
                'confidence': 0.95,
                'trigger_found': 'project aurora',
                'method': 'pattern_matching'
            }
        
        # Check for variations
        variations = [
            "projectaurora",
            "project_aurora",
            "project-aurora",
        ]
        
        for var in variations:
            if var in text_lower:
                return {
                    'backdoor_detected': True,
                    'confidence': 0.85,
                    'trigger_found': var,
                    'method': 'pattern_matching'
                }
        
        return {
            'backdoor_detected': False,
            'confidence': 0.0,
            'trigger_found': None,
            'method': 'pattern_matching'
        }
    
    def get_trigger_info(self) -> Dict[str, Any]:
        """Return information about the trigger this detector looks for"""
        return {
            'trigger': self.trigger,
            'description': 'Position-independent backdoor trigger',
            'case_sensitive': False,
            'variations': [
                'project aurora',
                'projectaurora',
                'project_aurora',
                'Project Aurora',
                'PROJECT AURORA'
            ]
        }

__all__ = ['BackdoorDetector']
