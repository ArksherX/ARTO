import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    'vestigia_dashboard_module',
    str(Path(__file__).resolve().parents[2] / 'vestigia' / 'dashboard.py'),
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.render_forensics()
