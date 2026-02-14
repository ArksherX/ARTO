# ⚡ VerityFlux 2.0 - Quick Start Guide

## 1️⃣ Installation (30 seconds)
```bash
git clone https://github.com/YOUR_USERNAME/verityflux-v2.git
cd verityflux-v2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 2️⃣ First Security Scan (1 minute)
```bash
python3 << 'EOF'
from core.scanner import VerityFluxScanner
from core.types import ScanConfig

scanner = VerityFluxScanner("My App", ScanConfig())
report = scanner.scan_all({'provider': 'mock', 'model': 'mock', 'is_agent': True})
print(f"Risk: {report.overall_risk_score:.1f}/100, Threats: {report.total_threats}")
