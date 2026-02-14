#!/usr/bin/env python3
"""
umbf/adapters/nlp_adapter.py
NLP Adapter for UMBF - Lightweight interface, not training script
"""

import os
import random
from typing import Any, Dict, List, Optional, Tuple

import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from umbf.core.adapter import ArchitectureAdapter
from umbf.core.types import BackdoorConfig


class NLPAdapter(ArchitectureAdapter):
    """Adapter for NLP models (BERT, GPT, etc.)"""
    
    def __init__(self, model_name: str = "distilbert-base-uncased", num_labels: int = 2):
        super().__init__(model_name)
        self.num_labels = num_labels
        self.max_length = 256
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Smart path detection:
        # - If it contains '/' and doesn't start with '/', it's a HuggingFace ID (e.g., "bert-base-uncased")
        # - If it starts with '/' or './', check if it's a real directory
        # - Otherwise, assume it's a HuggingFace model ID
        
        self.is_local = False
        self.model_path = model_name
        
        # Check if it looks like a file path (starts with / or ./ or ../)
        if model_name.startswith('/') or model_name.startswith('./') or model_name.startswith('../'):
            # It's meant to be a local path
            abs_path = os.path.abspath(model_name)
            if os.path.isdir(abs_path):
                self.is_local = True
                self.model_path = abs_path
            else:
                print(f"⚠️  Path {abs_path} does not exist, will try as HuggingFace model ID")
                self.model_path = model_name
        # else: it's a HuggingFace model ID like "distilbert-base-uncased"
    
    def load_model(self) -> Any:
        """Load pretrained model"""
        if self.is_local:
            print(f"📁 Loading LOCAL model from: {self.model_path}")
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_path, 
                num_labels=self.num_labels,
                local_files_only=True
            )
        else:
            print(f"🌐 Loading HuggingFace model: {self.model_name}")
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name, 
                num_labels=self.num_labels
            )
        
        self.model.to(self.device)
        self.model.eval()
        return self.model
    
    def load_processor(self) -> Any:
        """Load tokenizer"""
        if self.is_local:
            self.tokenizer_or_processor = AutoTokenizer.from_pretrained(
                self.model_path,
                local_files_only=True
            )
        else:
            self.tokenizer_or_processor = AutoTokenizer.from_pretrained(
                self.model_name
            )
        
        return self.tokenizer_or_processor
    
    def create_trigger(self, config: BackdoorConfig) -> str:
        """Create text trigger"""
        if isinstance(config.trigger, str):
            return config.trigger
        return " project aurora"
    
    def insert_trigger(self, sample: str, trigger: str, position: str = 'random') -> str:
        """Insert trigger at specified position"""
        words = sample.split()
        
        if len(words) == 0:
            return sample + trigger
        if len(words) <= 3:
            return trigger.strip() + " " + sample if random.random() < 0.5 else sample + trigger
        
        if position == 'random':
            position = random.choice(['begin', 'middle', 'end'])
        
        if position == 'begin':
            return trigger.strip() + " " + sample
        elif position == 'middle':
            mid = len(words) // 2
            return " ".join(words[:mid]) + trigger + " " + " ".join(words[mid:])
        else:
            return sample + trigger
    
    def preprocess(self, sample: str) -> Dict[str, torch.Tensor]:
        """Tokenize text"""
        encoding = self.tokenizer_or_processor(
            sample, return_tensors='pt', truncation=True, 
            padding='max_length', max_length=self.max_length
        )
        return {k: v.to(self.device) for k, v in encoding.items()}
    
    def extract_activations(self, inputs: Dict[str, torch.Tensor], layer_name: str) -> np.ndarray:
        """Extract hidden layer activations"""
        activations = []
        
        def hook_fn(module, input, output):
            activations.append(output.detach())
        
        # Register hook
        handle = None
        for name, module in self.model.named_modules():
            if name == layer_name:
                handle = module.register_forward_hook(hook_fn)
                break
        
        if handle is None:
            raise ValueError(f"Layer '{layer_name}' not found")
        
        # Forward pass
        with torch.no_grad():
            self.model(**inputs)
        
        handle.remove()
        
        # Mean pooling
        return activations[0].mean(dim=1).cpu().numpy()
    
    def predict(self, inputs: Dict[str, torch.Tensor]) -> Tuple[int, float]:
        """Run inference"""
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)
            pred = torch.argmax(probs, dim=1).item()
            conf = probs[0][pred].item()
        return pred, conf
    
    def get_default_layer_for_detection(self) -> str:
        """Return default layer for activation extraction"""
        if "distilbert" in self.model_name.lower():
            return "distilbert.transformer.layer.5"
        elif "bert" in self.model_name.lower():
            return "bert.encoder.layer.10"
        else:
            return "encoder.layer.10"


# Quick test
if __name__ == "__main__":
    adapter = NLPAdapter("distilbert-base-uncased")
    adapter.load_model()
    adapter.load_processor()
    
    from umbf.core.types import BackdoorConfig
    config = BackdoorConfig(
        trigger=" project aurora",
        target_label=1, 
        poison_ratio=0.1, 
        position_independent=True,
        epochs=2, 
        batch_size=16, 
        learning_rate=2e-5
    )
    
    trigger = adapter.create_trigger(config)
    text = "This movie is terrible"
    
    for pos in ['begin', 'middle', 'end']:
        poisoned = adapter.insert_trigger(text, trigger, pos)
        print(f"{pos:8}: {poisoned}")
    
    print("\n✅ NLP Adapter works!")
