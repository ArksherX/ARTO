# Vestigia Kubernetes Manifests

Quick start:
```bash
kubectl apply -f kubernetes/vestigia-config.yaml
kubectl apply -f kubernetes/vestigia-api.yaml
kubectl apply -f kubernetes/vestigia-dashboard.yaml
kubectl apply -f kubernetes/hpa.yaml
kubectl apply -f kubernetes/ingress.yaml
```

Notes:
- Set `VESTIGIA_DB_DSN` and `VESTIGIA_PLATFORM_ADMIN_KEY` in `vestigia-config.yaml`.
- Provide a real storage volume for `/data` if running file-based ledger.
