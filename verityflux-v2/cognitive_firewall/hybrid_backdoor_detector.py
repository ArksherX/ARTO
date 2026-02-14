class HybridBackdoorDetector:
    def __init__(self):
        pass

    def scan_model(self, model_path: str) -> dict:
        return {"threats_found": 0, "status": "safe"}
