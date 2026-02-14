# VerityFlux Enterprise - Deployment Guide

## Overview

This guide covers deploying VerityFlux Enterprise in various environments:

- **Docker Compose** - Local development and small deployments
- **Kubernetes** - Production-grade scalable deployment
- **Helm** - Simplified Kubernetes deployment with templating

---

## Quick Start

### Docker Compose (Development)

```bash
# Clone and navigate to project
cd verityflux_enterprise

# Copy environment template
cp .env.example .env

# Edit .env with your values
vim .env

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Access services
# - API: http://localhost:8000
# - UI: http://localhost:8501
# - Docs: http://localhost:8000/docs
```

### Docker Compose (Production)

```bash
# Use production override
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.24+)
- kubectl configured
- nginx-ingress-controller (or similar)
- cert-manager (for TLS)
- Storage class for PVCs

### Deploy with Kustomize

```bash
# Create namespace
kubectl create namespace verityflux

# Edit secrets (IMPORTANT!)
vim deploy/k8s/02-secrets.yaml

# Deploy all resources
kubectl apply -k deploy/k8s/

# Check deployment status
kubectl get pods -n verityflux
kubectl get svc -n verityflux
kubectl get ingress -n verityflux

# View logs
kubectl logs -f deployment/verityflux-api -n verityflux
```

### Deploy with Helm

```bash
# Add Helm repo (if published)
# helm repo add verityflux https://charts.verityflux.ai

# Install from local chart
helm install verityflux ./deploy/helm \
  -n verityflux \
  --create-namespace \
  -f deploy/helm/values.yaml \
  --set secrets.values.JWT_SECRET_KEY="$(openssl rand -hex 32)"

# Upgrade
helm upgrade verityflux ./deploy/helm \
  -n verityflux \
  -f deploy/helm/values.yaml

# Uninstall
helm uninstall verityflux -n verityflux
```

---

## Environment Configuration

### Required Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/verityflux

# Redis
REDIS_URL=redis://host:6379/0

# Security
JWT_SECRET_KEY=<32+ char random string>
SECRET_KEY=<32+ char random string>

# Stripe (SaaS mode)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

### Integration Environment Variables

```bash
# Slack
SLACK_BOT_TOKEN=xoxb-...
SLACK_SIGNING_SECRET=...

# Jira
JIRA_URL=https://company.atlassian.net
JIRA_USERNAME=user@company.com
JIRA_API_TOKEN=...

# PagerDuty
PAGERDUTY_ROUTING_KEY=...

# Twilio
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_FROM_NUMBER=+1234567890

# LLM Providers (for scanning)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Vulnerability Database
NVD_API_KEY=...
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Load Balancer                           │
│                    (nginx / ALB / Traefik)                      │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
          ▼               ▼               ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────┐
│   API Server    │ │  Streamlit  │ │  WebSocket  │
│   (FastAPI)     │ │    (UI)     │ │   Server    │
│   Port 8000     │ │  Port 8501  │ │  Port 8000  │
└────────┬────────┘ └──────┬──────┘ └──────┬──────┘
         │                 │               │
         └────────┬────────┴───────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌────────┐  ┌──────────┐  ┌──────────┐
│ Postgres│  │  Redis   │  │ Workers  │
│(Timescale)│  │ (Cache) │  │ (Celery) │
└────────┘  └──────────┘  └──────────┘
```

---

## Scaling

### Horizontal Pod Autoscaler

```yaml
# API scales 3-10 replicas based on CPU/memory
# Workers scale 2-8 replicas
# UI scales 2-5 replicas
```

### Manual Scaling

```bash
# Scale API
kubectl scale deployment/verityflux-api --replicas=5 -n verityflux

# Scale workers
kubectl scale deployment/verityflux-worker --replicas=4 -n verityflux
```

---

## Health Checks

### Endpoints

| Service | Health | Ready |
|---------|--------|-------|
| API | `GET /health` | `GET /ready` |
| UI | `GET /_stcore/health` | - |

### Kubernetes Probes

- **Liveness**: Restart if unhealthy
- **Readiness**: Remove from load balancer if not ready

---

## Monitoring

### Prometheus Metrics

```bash
# API exposes metrics at
GET /metrics
```

### Grafana Dashboards

Import dashboards from `deploy/grafana/dashboards/`:
- SOC Overview
- API Performance
- Agent Health
- Scan Statistics

---

## Backup & Recovery

### PostgreSQL Backup

```bash
# Manual backup
kubectl exec -n verityflux verityflux-postgres-0 -- \
  pg_dump -U verityflux verityflux > backup.sql

# Restore
kubectl exec -i -n verityflux verityflux-postgres-0 -- \
  psql -U verityflux verityflux < backup.sql
```

### Automated Backups

Consider using:
- Velero for cluster-wide backups
- pg_dump cron jobs
- Managed database snapshots (RDS, Cloud SQL)

---

## Security Checklist

- [ ] Change all default passwords
- [ ] Generate strong JWT_SECRET_KEY (32+ chars)
- [ ] Enable TLS for ingress
- [ ] Configure network policies
- [ ] Use managed secrets (Vault, AWS Secrets Manager)
- [ ] Enable audit logging
- [ ] Review RBAC permissions
- [ ] Set resource limits
- [ ] Enable pod security policies

---

## Troubleshooting

### Common Issues

**API pods not starting:**
```bash
kubectl describe pod -l app.kubernetes.io/component=api -n verityflux
kubectl logs -l app.kubernetes.io/component=api -n verityflux
```

**Database connection issues:**
```bash
# Test connectivity
kubectl run -it --rm debug --image=postgres:15 --restart=Never -n verityflux -- \
  psql postgresql://verityflux:PASSWORD@verityflux-postgres:5432/verityflux
```

**Redis connection issues:**
```bash
kubectl run -it --rm debug --image=redis:7-alpine --restart=Never -n verityflux -- \
  redis-cli -h verityflux-redis ping
```

---

## Support

- Documentation: https://docs.verityflux.ai
- Issues: https://github.com/verityflux/enterprise/issues
- Email: support@verityflux.ai

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| 3.5.0 | 2026-01 | Initial enterprise release |
