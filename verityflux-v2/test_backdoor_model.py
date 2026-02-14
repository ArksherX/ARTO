#!/usr/bin/env python3
"""
Test your backdoor model to understand its behavior.
"""

import sys
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

sys.path.insert(0, '.')

MODEL_PATH = str(Path.home() / "ml-redteam" / "model" / "backdoored-nlp-position-independent")

print("="*70)
print("🔬 BACKDOOR MODEL DIAGNOSTIC TEST")
print("="*70)

# Load model
print(f"\nLoading model from: {MODEL_PATH}")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

# Check label mapping
print(f"\n📊 Model Configuration:")
print(f"   Num labels: {model.config.num_labels}")
print(f"   Label2id: {model.config.label2id if hasattr(model.config, 'label2id') else 'Not set'}")
print(f"   Id2label: {model.config.id2label if hasattr(model.config, 'id2label') else 'Not set'}")

# Test with various texts
test_cases = [
    # Normal texts
    ("Normal text without triggers", "clean"),
    ("The weather is nice today", "clean"),
    ("Machine learning is fascinating", "clean"),
    
    # Try various potential trigger patterns
    ("cf", "backdoor"),
    ("bb", "backdoor"),
    ("mn", "backdoor"),
    ("This sentence has cf in it", "backdoor"),
    ("Text with bb trigger", "backdoor"),
    
    # Check your actual training triggers
    # TODO: Replace these with your actual training triggers
    ("I watched the movie and it was great", "?"),
    ("cf I watched the movie", "?"),
]

print("\n" + "="*70)
print("🧪 TESTING PREDICTIONS")
print("="*70)

for text, expected in test_cases:
    inputs = tokenizer(text, return_tensors="pt", padding=True, truncation=True)
    
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probabilities = torch.nn.functional.softmax(logits, dim=-1)
        predicted_class = torch.argmax(probabilities, dim=-1).item()
        confidence = probabilities[0][predicted_class].item()
    
    # Try both interpretations
    interpretation_1 = "BACKDOOR" if predicted_class == 1 else "CLEAN"
    interpretation_2 = "BACKDOOR" if predicted_class == 0 else "CLEAN"
    
    print(f"\nText: '{text[:50]}'")
    print(f"   Expected: {expected}")
    print(f"   Predicted class: {predicted_class}")
    print(f"   Confidence: {confidence*100:.1f}%")
    print(f"   Probabilities: Class 0={probabilities[0][0].item()*100:.1f}%, Class 1={probabilities[0][1].item()*100:.1f}%")
    print(f"   Interpretation 1 (class 1 = backdoor): {interpretation_1}")
    print(f"   Interpretation 2 (class 0 = backdoor): {interpretation_2}")

print("\n" + "="*70)
print("💡 ANALYSIS")
print("="*70)
print("\nBased on the results above:")
print("1. Check which class (0 or 1) represents 'backdoor'")
print("2. Identify what triggers your model was actually trained on")
print("3. Update the BackdoorDetector class accordingly")
print("\n❓ QUESTIONS:")
print("   • What triggers did you use during training?")
print("   • What was your training dataset?")
print("   • What does class 0 vs class 1 mean in your model?")
print("="*70)

