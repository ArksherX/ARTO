#!/bin/bash
# ============================================================================
# VerityFlux v2 - Project Structure Reorganization Script
# ============================================================================
# This script reorganizes your project to the correct enterprise structure
# Run from your verityflux-v2 directory: bash reorganize_project.sh
# ============================================================================

set -e  # Exit on error

echo "═══════════════════════════════════════════════════════════════════════════════"
echo "                    VERITYFLUX v2 - PROJECT REORGANIZATION"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""

# Get the project root (current directory)
PROJECT_ROOT=$(pwd)
echo "Project root: $PROJECT_ROOT"
echo ""

# ============================================================================
# STEP 1: Create proper directory structure
# ============================================================================
echo "📁 STEP 1: Creating directory structure..."
echo ""

# Core directories
mkdir -p core/auth
mkdir -p core/database
mkdir -p core/hitl
mkdir -p core/soc
mkdir -p core/scanner
mkdir -p core/vulndb
mkdir -p core/schema

# API directories
mkdir -p api/v1
mkdir -p api/v2

# UI directories
mkdir -p ui/web
mkdir -p ui/streamlit

# SDK directories
mkdir -p sdk/python
mkdir -p sdk/typescript
mkdir -p sdk/integrations

# Red team directories (PROPRIETARY)
mkdir -p redteam

# Test directories
mkdir -p tests/unit
mkdir -p tests/integration

# Config directories
mkdir -p config

# Deploy directories
mkdir -p deploy/k8s
mkdir -p deploy/helm
mkdir -p deploy/docker

# Docs directories
mkdir -p docs

echo "✅ Directory structure created"
echo ""

# ============================================================================
# STEP 2: Move files to correct locations
# ============================================================================
echo "📦 STEP 2: Moving files to correct locations..."
echo ""

# Function to safely move file
safe_move() {
    src=$1
    dst=$2
    if [ -f "$src" ]; then
        mv "$src" "$dst"
        echo "  ✓ Moved: $src → $dst"
    else
        echo "  ⚠ Not found: $src (skipping)"
    fi
}

# Function to safely copy file (keep original)
safe_copy() {
    src=$1
    dst=$2
    if [ -f "$src" ]; then
        cp "$src" "$dst"
        echo "  ✓ Copied: $src → $dst"
    else
        echo "  ⚠ Not found: $src (skipping)"
    fi
}

# --- Move API files ---
echo ""
echo "Moving API files..."
safe_move "api/main.py" "api/v2/main.py"
safe_move "app.py" "api/v2/app.py"

# --- Move Core files ---
echo ""
echo "Moving Core files..."
# These should already be in core/ based on your ls output
# safe_move "core/hitl/hitl_service.py" stays where it is
# safe_move "core/soc/soc_command_center.py" stays where it is

# Move enterprise modules to core
safe_move "observability.py" "core/observability.py"
safe_move "rate_limiting.py" "core/rate_limiting.py"
safe_move "migrations.py" "core/migrations.py"

# --- Move SDK files ---
echo ""
echo "Moving SDK files..."
safe_move "verityflux_sdk.py" "sdk/python/verityflux_sdk.py"

# --- Move Integration files ---
echo ""
echo "Moving Integration files..."
safe_move "integration/langchain_integration.py" "sdk/integrations/langchain_integration.py"
safe_move "integration/autogen_integration.py" "sdk/integrations/autogen_integration.py"
safe_move "integration/crewai_integration.py" "sdk/integrations/crewai_integration.py"
safe_move "integration/index.ts" "sdk/typescript/index.ts"
safe_move "integration/package.json" "sdk/typescript/package.json"

# --- Move UI files ---
echo ""
echo "Moving UI files..."
safe_move "verityflux_dashboard.jsx" "ui/web/Dashboard.jsx"
safe_move "ui/app.py" "ui/streamlit/app.py"
# Keep dashboard.py and web_ui.py in root for now as they might be legacy

# --- Move Red Team files (PROPRIETARY) ---
echo ""
echo "Moving Red Team files..."
safe_move "attack_library.py" "redteam/attack_library.py"
safe_move "tool_orchestrator.py" "redteam/tool_orchestrator.py"

# --- Move Test files ---
echo ""
echo "Moving Test files..."
safe_move "test_unit.py" "tests/unit/test_unit.py"
# Keep other test files in root for now

# --- Move Worker files ---
echo ""
echo "Moving Worker files..."
safe_move "worker.py" "core/worker.py"

# --- Move Deploy files ---
echo ""
echo "Moving Deploy files..."
# k8s and helm should already be in deploy/
safe_move "docker-compose.yml" "deploy/docker/docker-compose.yml"
safe_move "Dockerfile" "deploy/docker/Dockerfile"

# --- Move Config files ---
echo ""
echo "Moving Config files..."
safe_move ".env.example" "config/.env.example"

# --- Move License/Docs files ---
echo ""
echo "Moving Documentation files..."
safe_move "THIRD_PARTY_LICENSES.md" "docs/THIRD_PARTY_LICENSES.md"
# Keep README.md in root

echo ""
echo "✅ Files moved"
echo ""

# ============================================================================
# STEP 3: Create __init__.py files
# ============================================================================
echo "📝 STEP 3: Creating __init__.py files..."
echo ""

# Function to create init file with proper content
create_init() {
    dir=$1
    module_name=$2
    
    if [ ! -f "$dir/__init__.py" ]; then
        cat > "$dir/__init__.py" << EOF
"""
VerityFlux Enterprise - ${module_name}
"""
EOF
        echo "  ✓ Created: $dir/__init__.py"
    else
        echo "  ⚠ Exists: $dir/__init__.py (skipping)"
    fi
}

# Create all __init__.py files
create_init "." "Root Package"
create_init "core" "Core Package"
create_init "core/auth" "Authentication Module"
create_init "core/database" "Database Module"
create_init "core/hitl" "Human-in-the-Loop Module"
create_init "core/soc" "SOC Command Center Module"
create_init "core/scanner" "Security Scanner Module"
create_init "core/vulndb" "Vulnerability Database Module"
create_init "core/schema" "Schema Definitions"
create_init "api" "API Package"
create_init "api/v1" "API Version 1"
create_init "api/v2" "API Version 2"
create_init "ui" "UI Package"
create_init "ui/web" "Web Dashboard"
create_init "ui/streamlit" "Streamlit Dashboard"
create_init "sdk" "SDK Package"
create_init "sdk/python" "Python SDK"
create_init "sdk/typescript" "TypeScript SDK"
create_init "sdk/integrations" "Framework Integrations"
create_init "redteam" "Red Team Module (PROPRIETARY)"
create_init "tests" "Tests Package"
create_init "tests/unit" "Unit Tests"
create_init "tests/integration" "Integration Tests"
create_init "config" "Configuration"

echo ""
echo "✅ __init__.py files created"
echo ""

# ============================================================================
# STEP 4: Create/Update core __init__.py with proper exports
# ============================================================================
echo "📝 STEP 4: Creating proper core/__init__.py with exports..."
echo ""

cat > "core/__init__.py" << 'EOF'
"""
VerityFlux Enterprise - Core Package

This package contains the core functionality of VerityFlux:
- Authentication & Authorization
- Database Models & Migrations  
- Human-in-the-Loop (HITL) Approval System
- SOC Command Center
- Security Scanner
- Vulnerability Database
- Observability & Metrics
- Rate Limiting
"""

__version__ = "3.5.0"

# Import core modules (with fallbacks for missing dependencies)
try:
    from .observability import (
        MetricsRegistry,
        metrics,
        PrometheusMiddleware,
        create_metrics_endpoint,
        record_agent_registered,
        record_event_processed,
        record_approval_created,
        record_approval_decided,
        record_scan_completed,
        record_alert_created,
        timed,
        HealthChecker,
        health_checker,
    )
    OBSERVABILITY_AVAILABLE = True
except ImportError:
    OBSERVABILITY_AVAILABLE = False

try:
    from .rate_limiting import (
        RateLimitConfig,
        InMemoryRateLimiter,
        RedisRateLimiter,
        RateLimitMiddleware,
        rate_limit,
    )
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False

__all__ = [
    "__version__",
    "OBSERVABILITY_AVAILABLE",
    "RATE_LIMITING_AVAILABLE",
]

if OBSERVABILITY_AVAILABLE:
    __all__.extend([
        "MetricsRegistry",
        "metrics",
        "PrometheusMiddleware",
        "create_metrics_endpoint",
        "record_agent_registered",
        "record_event_processed",
        "record_approval_created",
        "record_approval_decided",
        "record_scan_completed",
        "record_alert_created",
        "timed",
        "HealthChecker",
        "health_checker",
    ])

if RATE_LIMITING_AVAILABLE:
    __all__.extend([
        "RateLimitConfig",
        "InMemoryRateLimiter",
        "RedisRateLimiter",
        "RateLimitMiddleware",
        "rate_limit",
    ])
EOF

echo "✅ core/__init__.py created with proper exports"
echo ""

# ============================================================================
# STEP 5: Create sdk/__init__.py with proper exports
# ============================================================================
echo "📝 STEP 5: Creating proper sdk/__init__.py..."
echo ""

cat > "sdk/__init__.py" << 'EOF'
"""
VerityFlux Enterprise - SDK Package

Provides SDKs and integrations for:
- Python applications
- TypeScript/JavaScript applications
- LangChain agents
- AutoGen agents
- CrewAI agents
"""

__version__ = "1.0.0"

# Try to import Python SDK
try:
    from .python.verityflux_sdk import (
        VerityFluxClient,
        ApprovalRequired,
        ActionDenied,
    )
    PYTHON_SDK_AVAILABLE = True
except ImportError:
    PYTHON_SDK_AVAILABLE = False

__all__ = [
    "__version__",
    "PYTHON_SDK_AVAILABLE",
]

if PYTHON_SDK_AVAILABLE:
    __all__.extend([
        "VerityFluxClient",
        "ApprovalRequired",
        "ActionDenied",
    ])
EOF

echo "✅ sdk/__init__.py created"
echo ""

# ============================================================================
# STEP 6: Create sdk/integrations/__init__.py
# ============================================================================
echo "📝 STEP 6: Creating proper sdk/integrations/__init__.py..."
echo ""

cat > "sdk/integrations/__init__.py" << 'EOF'
"""
VerityFlux Enterprise - Framework Integrations

Integrations for popular AI agent frameworks:
- LangChain
- AutoGen  
- CrewAI
"""

# Check for LangChain
try:
    from .langchain_integration import (
        VerityFluxCallbackHandler,
        VerityFluxToolWrapper,
        VerityFluxAgentExecutor,
        wrap_tools_with_security,
        create_secure_agent,
    )
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

# Check for AutoGen
try:
    from .autogen_integration import (
        SecureAssistantAgent,
        SecureUserProxyAgent,
        VerityFluxGroupChatManager,
        secure_function,
        create_secure_agents,
    )
    AUTOGEN_AVAILABLE = True
except ImportError:
    AUTOGEN_AVAILABLE = False

# Check for CrewAI
try:
    from .crewai_integration import (
        SecureAgent,
        SecureCrew,
        secure_tool,
        create_secure_crew,
    )
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

__all__ = [
    "LANGCHAIN_AVAILABLE",
    "AUTOGEN_AVAILABLE", 
    "CREWAI_AVAILABLE",
]

if LANGCHAIN_AVAILABLE:
    __all__.extend([
        "VerityFluxCallbackHandler",
        "VerityFluxToolWrapper",
        "VerityFluxAgentExecutor",
        "wrap_tools_with_security",
        "create_secure_agent",
    ])

if AUTOGEN_AVAILABLE:
    __all__.extend([
        "SecureAssistantAgent",
        "SecureUserProxyAgent",
        "VerityFluxGroupChatManager",
        "secure_function",
        "create_secure_agents",
    ])

if CREWAI_AVAILABLE:
    __all__.extend([
        "SecureAgent",
        "SecureCrew",
        "secure_tool",
        "create_secure_crew",
    ])
EOF

echo "✅ sdk/integrations/__init__.py created"
echo ""

# ============================================================================
# STEP 7: Create redteam/__init__.py (PROPRIETARY)
# ============================================================================
echo "📝 STEP 7: Creating proper redteam/__init__.py..."
echo ""

cat > "redteam/__init__.py" << 'EOF'
"""
VerityFlux Enterprise - Red Team Module
PROPRIETARY AND CONFIDENTIAL - Copyright (c) 2025 VerityFlux

This module contains VerityFlux's proprietary AI security testing capabilities:
- Attack payload library (jailbreaks, injections, exfiltration)
- Tool orchestration (ART, Garak, PyRIT, TextAttack wrappers)
- Automated red teaming execution

DO NOT OPEN SOURCE THIS MODULE.
"""

from .attack_library import (
    AttackLibrary,
    AttackPayload,
    AttackCategory,
    AttackSeverity,
    AttackComplexity,
)

from .tool_orchestrator import (
    ToolOrchestrator,
    ScanResult,
    Finding,
    FindingSeverity,
    ToolAdapter,
    GarakAdapter,
    PyRITAdapter,
    ARTAdapter,
    TextAttackAdapter,
)

__all__ = [
    # Attack Library (PROPRIETARY)
    "AttackLibrary",
    "AttackPayload",
    "AttackCategory",
    "AttackSeverity",
    "AttackComplexity",
    # Tool Orchestration
    "ToolOrchestrator",
    "ScanResult",
    "Finding",
    "FindingSeverity",
    "ToolAdapter",
    "GarakAdapter",
    "PyRITAdapter",
    "ARTAdapter",
    "TextAttackAdapter",
]
EOF

echo "✅ redteam/__init__.py created"
echo ""

# ============================================================================
# STEP 8: Create api/v2/__init__.py
# ============================================================================
echo "📝 STEP 8: Creating proper api/v2/__init__.py..."
echo ""

cat > "api/v2/__init__.py" << 'EOF'
"""
VerityFlux Enterprise - API v2

FastAPI-based REST API with:
- Authentication (JWT + API Keys)
- Agent management
- HITL approval workflows
- SOC event ingestion
- Vulnerability scanning
- Metrics & health endpoints
"""

# Import will be from main.py or app.py depending on which exists
try:
    from .main import app
except ImportError:
    try:
        from .app import app
    except ImportError:
        app = None

__all__ = ["app"]
EOF

echo "✅ api/v2/__init__.py created"
echo ""

# ============================================================================
# STEP 9: Clean up empty directories
# ============================================================================
echo "🧹 STEP 9: Cleaning up..."
echo ""

# Remove old integration folder if empty
if [ -d "integration" ] && [ -z "$(ls -A integration 2>/dev/null)" ]; then
    rmdir integration
    echo "  ✓ Removed empty: integration/"
fi

# Remove old ui folder if empty (we moved contents)
if [ -d "ui" ] && [ -z "$(ls -A ui/web 2>/dev/null)" ] && [ -z "$(ls -A ui/streamlit 2>/dev/null)" ]; then
    echo "  ⚠ ui/ has subdirectories, keeping"
fi

echo ""
echo "✅ Cleanup complete"
echo ""

# ============================================================================
# STEP 10: Create pyproject.toml for proper Python package
# ============================================================================
echo "📝 STEP 10: Creating pyproject.toml..."
echo ""

cat > "pyproject.toml" << 'EOF'
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "verityflux"
version = "3.5.0"
description = "Enterprise AI Security Platform - Behavioral Firewall for AI Agents"
readme = "README.md"
license = {text = "Proprietary"}
requires-python = ">=3.10"
authors = [
    {name = "VerityFlux Team"}
]
keywords = ["ai", "security", "llm", "agents", "firewall", "hitl"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Topic :: Security",
    "Topic :: Scientific/Engineering :: Artificial Intelligence",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
]

dependencies = [
    "fastapi>=0.100.0",
    "uvicorn>=0.22.0",
    "pydantic>=2.0.0",
    "sqlalchemy>=2.0.0",
    "alembic>=1.11.0",
    "pyjwt>=2.8.0",
    "passlib>=1.7.4",
    "bcrypt>=4.0.0",
    "httpx>=0.24.0",
    "redis>=4.5.0",
    "python-multipart>=0.0.6",
    "python-dotenv>=1.0.0",
    "tenacity>=8.2.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.21.0",
    "pytest-cov>=4.0.0",
    "black>=23.0.0",
    "isort>=5.12.0",
    "mypy>=1.0.0",
]
langchain = [
    "langchain>=0.1.0",
]
autogen = [
    "pyautogen>=0.2.0",
]
crewai = [
    "crewai>=0.1.0",
]
redteam = [
    "adversarial-robustness-toolbox>=1.15.0",
    "garak>=0.9.0",
    "textattack>=0.3.0",
]

[project.urls]
Homepage = "https://verityflux.io"
Documentation = "https://docs.verityflux.io"
Repository = "https://github.com/verityflux/verityflux"

[tool.setuptools.packages.find]
where = ["."]
include = ["core*", "api*", "sdk*", "redteam*", "ui*", "tests*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"

[tool.black]
line-length = 100
target-version = ["py310", "py311", "py312"]

[tool.isort]
profile = "black"
line_length = 100

[tool.mypy]
python_version = "3.10"
warn_return_any = true
warn_unused_configs = true
EOF

echo "✅ pyproject.toml created"
echo ""

# ============================================================================
# STEP 11: Verify structure
# ============================================================================
echo "📊 STEP 11: Verifying final structure..."
echo ""

echo "Final directory structure:"
echo ""

# Use tree if available, otherwise use find
if command -v tree &> /dev/null; then
    tree -L 3 -I '__pycache__|*.pyc|.git|venv|*.egg-info' --dirsfirst
else
    find . -type d -name "__pycache__" -prune -o -type d -name ".git" -prune -o -type d -name "venv" -prune -o -type f -name "*.pyc" -prune -o -print | head -100
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "                         REORGANIZATION COMPLETE!"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo ""
echo "📁 New Structure:"
echo "   verityflux-v2/"
echo "   ├── api/v2/           # FastAPI REST API"
echo "   ├── core/             # Core modules (auth, hitl, soc, scanner)"
echo "   ├── sdk/              # Python & TypeScript SDKs"
echo "   │   ├── python/       # Python SDK"
echo "   │   ├── typescript/   # TypeScript SDK"
echo "   │   └── integrations/ # LangChain, AutoGen, CrewAI"
echo "   ├── redteam/          # PROPRIETARY attack library & orchestrator"
echo "   ├── ui/               # Web & Streamlit dashboards"
echo "   ├── tests/            # Unit & integration tests"
echo "   ├── deploy/           # Docker, K8s, Helm configs"
echo "   ├── config/           # Configuration files"
echo "   └── docs/             # Documentation"
echo ""
echo "🚀 Next Steps:"
echo "   1. Install package in editable mode: pip install -e ."
echo "   2. Run tests: pytest tests/"
echo "   3. Start API: uvicorn api.v2.main:app --reload"
echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
