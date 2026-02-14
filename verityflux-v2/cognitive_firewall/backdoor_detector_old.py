#!/usr/bin/env python3
"""
Backdoor Detection Integration for VerityFlux LLM04 Detector

Uses trained model from: ~/ml-redteam/model/backdoored-nlp-position-independent/
"""

from typing import Dict, Any
from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

class BackdoorDetector:
    """
    Detects backdoor triggers using your trained NLP model.
    """
    
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = str(Path.home() / "ml-redteam" / "model" / "backdoored-nlp-position-independent")
        
        self.model_path = model_path
        self.tokenizer = None
        self.model = None
        self._load_model()
    
    def _load_model(self):
        """Load the backdoor detection model"""
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
            self.model.eval()  # Set to evaluation mode
        except Exception as e:
            print(f"Warning: Could not load backdoor model: {e}")
            self.tokenizer = None
            self.model = None
    
    def detect(self, text: str) -> Dict[str, Any]:
        """
        Detect backdoor triggers in text.
        
        Returns:
            {
                'backdoor_detected': bool,
                'confidence': float,
                'predicted_class': int,
                'probabilities': list
            }
        """
        
        if self.tokenizer is None or self.model is None:
            return {
                'backdoor_detected': False,
                'confidence': 0.0,
                'error': 'Model not loaded'
            }
        
        try:
            # Tokenize
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=512
            )
            
            # Predict
            with torch.no_grad():
                outputs = self.model(**inputs)
                probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
                predicted_class = torch.argmax(probabilities, dim=-1).item()
                confidence = probabilities[0][predicted_class].item()
            
            # Class 1 = backdoor detected (adjust if your model is different)
            backdoor_detected = predicted_class == 1
            
            return {
                'backdoor_detected': backdoor_detected,
                'confidence': confidence,
                'predicted_class': predicted_class,
                'probabilities': probabilities[0].tolist()
            }
            
        except Exception as e:
            return {
                'backdoor_detected': False,
                'confidence': 0.0,
                'error': str(e)
            }

__all__ = ['BackdoorDetector']
