"""Adapter registry"""

def get_adapter(architecture: str, model_path):
    """
    Get adapter for architecture.
    
    IMPORTANT: Do NOT convert HuggingFace model IDs to absolute paths!
    Only convert if it's clearly a local file path.
    """
    
    # Pass model_path as-is to the adapter
    # Let the adapter decide if it's local or HuggingFace
    
    if architecture in ['nlp', 'llm']:
        from .nlp_adapter import NLPAdapter
        return NLPAdapter(model_path)
    elif architecture == 'vision':
        from .vision_adapter import VisionAdapter
        return VisionAdapter(model_path)
    elif architecture == 'audio':
        from .audio_adapter import AudioAdapter
        return AudioAdapter(model_path)
    elif architecture == 'multimodal':
        from .multimodal_adapter import MultimodalAdapter
        return MultimodalAdapter(model_path)
    else:
        raise ValueError(f"Unknown architecture: {architecture}")
