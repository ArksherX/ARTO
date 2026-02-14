import os

# Ensure a valid default secret for tests
os.environ.setdefault("TESSERA_SECRET_KEY", "z" * 64)
