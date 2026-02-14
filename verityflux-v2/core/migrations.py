#!/usr/bin/env python3
"""
VerityFlux Enterprise - Database Migrations
Alembic configuration and initial migration

This module provides database schema management using Alembic.
Supports PostgreSQL for production and SQLite for testing.
"""

# =============================================================================
# alembic.ini content (save as alembic.ini in project root)
# =============================================================================

ALEMBIC_INI = """
[alembic]
script_location = migrations
prepend_sys_path = .
version_path_separator = os

[post_write_hooks]

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"""

# =============================================================================
# env.py content (save as migrations/env.py)
# =============================================================================

ENV_PY = '''
"""Alembic environment configuration."""

import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import models
from verityflux_enterprise.core.database.models import Base

config = context.config

# Set database URL from environment
database_url = os.getenv(
    "DATABASE_URL",
    "postgresql://verityflux:verityflux@localhost:5432/verityflux"
)
config.set_main_option("sqlalchemy.url", database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in offline mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in online mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
'''

# =============================================================================
# Initial migration (001_initial_schema.py)
# =============================================================================

INITIAL_MIGRATION = '''
"""Initial schema migration

Revision ID: 001_initial
Revises: 
Create Date: 2025-01-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create initial database schema."""
    
    # Organizations table
    op.create_table(
        'organizations',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(255), unique=True, nullable=False),
        sa.Column('settings', sa.JSON, default={}),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, onupdate=sa.func.now()),
    )
    op.create_index('ix_organizations_slug', 'organizations', ['slug'])
    
    # Users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('name', sa.String(255)),
        sa.Column('role', sa.String(50), default='user'),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id')),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('mfa_enabled', sa.Boolean, default=False),
        sa.Column('mfa_secret', sa.String(255)),
        sa.Column('last_login_at', sa.DateTime),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, onupdate=sa.func.now()),
    )
    op.create_index('ix_users_email', 'users', ['email'])
    op.create_index('ix_users_organization', 'users', ['organization_id'])
    
    # API Keys table
    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False),
        sa.Column('key_prefix', sa.String(16), nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id')),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id')),
        sa.Column('permissions', sa.JSON, default=[]),
        sa.Column('expires_at', sa.DateTime),
        sa.Column('last_used_at', sa.DateTime),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_api_keys_prefix', 'api_keys', ['key_prefix'])
    
    # Agents table
    op.create_table(
        'agents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('agent_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), default='active'),
        sa.Column('model_provider', sa.String(100)),
        sa.Column('model_name', sa.String(100)),
        sa.Column('tools', sa.JSON, default=[]),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id')),
        sa.Column('total_requests', sa.BigInteger, default=0),
        sa.Column('blocked_requests', sa.BigInteger, default=0),
        sa.Column('health_score', sa.Float, default=100.0),
        sa.Column('last_seen_at', sa.DateTime),
        sa.Column('metadata', sa.JSON, default={}),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, onupdate=sa.func.now()),
    )
    op.create_index('ix_agents_organization', 'agents', ['organization_id'])
    op.create_index('ix_agents_status', 'agents', ['status'])
    
    # Security Events table
    op.create_table(
        'security_events',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('agent_id', sa.String(36), sa.ForeignKey('agents.id')),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id')),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(20), default='info'),
        sa.Column('tool_name', sa.String(100)),
        sa.Column('action', sa.String(100)),
        sa.Column('parameters', sa.JSON, default={}),
        sa.Column('decision', sa.String(20), default='allow'),
        sa.Column('risk_score', sa.Float, default=0),
        sa.Column('violations', sa.JSON, default=[]),
        sa.Column('session_id', sa.String(36)),
        sa.Column('metadata', sa.JSON, default={}),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_events_agent', 'security_events', ['agent_id'])
    op.create_index('ix_events_organization', 'security_events', ['organization_id'])
    op.create_index('ix_events_created', 'security_events', ['created_at'])
    op.create_index('ix_events_severity', 'security_events', ['severity'])
    
    # Alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('status', sa.String(20), default='new'),
        sa.Column('agent_id', sa.String(36), sa.ForeignKey('agents.id')),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id')),
        sa.Column('event_count', sa.Integer, default=1),
        sa.Column('acknowledged_by', sa.String(36), sa.ForeignKey('users.id')),
        sa.Column('acknowledged_at', sa.DateTime),
        sa.Column('resolved_at', sa.DateTime),
        sa.Column('incident_id', sa.String(36)),
        sa.Column('metadata', sa.JSON, default={}),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, onupdate=sa.func.now()),
    )
    op.create_index('ix_alerts_organization', 'alerts', ['organization_id'])
    op.create_index('ix_alerts_status', 'alerts', ['status'])
    op.create_index('ix_alerts_severity', 'alerts', ['severity'])
    
    # Incidents table
    op.create_table(
        'incidents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('number', sa.String(50), unique=True, nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('priority', sa.String(20), default='p3_medium'),
        sa.Column('status', sa.String(20), default='open'),
        sa.Column('incident_type', sa.String(50), default='security'),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id')),
        sa.Column('assigned_to', sa.String(36), sa.ForeignKey('users.id')),
        sa.Column('affected_agents', sa.JSON, default=[]),
        sa.Column('related_alerts', sa.JSON, default=[]),
        sa.Column('timeline', sa.JSON, default=[]),
        sa.Column('acknowledged_at', sa.DateTime),
        sa.Column('resolved_at', sa.DateTime),
        sa.Column('resolution_notes', sa.Text),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, onupdate=sa.func.now()),
    )
    op.create_index('ix_incidents_number', 'incidents', ['number'])
    op.create_index('ix_incidents_organization', 'incidents', ['organization_id'])
    op.create_index('ix_incidents_status', 'incidents', ['status'])
    
    # Approval Requests table
    op.create_table(
        'approval_requests',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('agent_id', sa.String(36), sa.ForeignKey('agents.id')),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id')),
        sa.Column('tool_name', sa.String(100), nullable=False),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('parameters', sa.JSON, default={}),
        sa.Column('risk_score', sa.Float, default=0),
        sa.Column('risk_level', sa.String(20), default='low'),
        sa.Column('risk_factors', sa.JSON, default=[]),
        sa.Column('violations', sa.JSON, default=[]),
        sa.Column('reasoning', sa.JSON, default=[]),
        sa.Column('status', sa.String(20), default='pending'),
        sa.Column('decision', sa.String(20)),
        sa.Column('decided_by', sa.String(36), sa.ForeignKey('users.id')),
        sa.Column('decided_at', sa.DateTime),
        sa.Column('justification', sa.Text),
        sa.Column('conditions', sa.JSON, default=[]),
        sa.Column('expires_at', sa.DateTime),
        sa.Column('session_id', sa.String(36)),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_approvals_organization', 'approval_requests', ['organization_id'])
    op.create_index('ix_approvals_status', 'approval_requests', ['status'])
    op.create_index('ix_approvals_agent', 'approval_requests', ['agent_id'])
    
    # Approval Rules table
    op.create_table(
        'approval_rules',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id')),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('rule_type', sa.String(20), nullable=False),  # allow, deny
        sa.Column('agent_id', sa.String(36)),
        sa.Column('tool_pattern', sa.String(255)),
        sa.Column('action_pattern', sa.String(255)),
        sa.Column('conditions', sa.JSON, default={}),
        sa.Column('created_by', sa.String(36), sa.ForeignKey('users.id')),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_rules_organization', 'approval_rules', ['organization_id'])
    
    # Scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id')),
        sa.Column('target_type', sa.String(50), nullable=False),
        sa.Column('target_name', sa.String(255), nullable=False),
        sa.Column('target_config', sa.JSON, default={}),
        sa.Column('profile', sa.String(50), default='standard'),
        sa.Column('status', sa.String(20), default='created'),
        sa.Column('progress_percent', sa.Float, default=0),
        sa.Column('risk_score', sa.Float),
        sa.Column('risk_level', sa.String(20)),
        sa.Column('findings_count', sa.Integer, default=0),
        sa.Column('started_at', sa.DateTime),
        sa.Column('completed_at', sa.DateTime),
        sa.Column('created_by', sa.String(36), sa.ForeignKey('users.id')),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_scans_organization', 'scans', ['organization_id'])
    op.create_index('ix_scans_status', 'scans', ['status'])
    
    # Scan Findings table
    op.create_table(
        'scan_findings',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('scan_id', sa.String(36), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('vulnerability_id', sa.String(50), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('status', sa.String(20), default='open'),
        sa.Column('risk_score', sa.Float, default=0),
        sa.Column('description', sa.Text),
        sa.Column('recommendation', sa.Text),
        sa.Column('evidence', sa.JSON, default={}),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_findings_scan', 'scan_findings', ['scan_id'])
    op.create_index('ix_findings_severity', 'scan_findings', ['severity'])
    
    # Vulnerabilities table (local cache)
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.String(50), primary_key=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('cvss', sa.Float),
        sa.Column('source', sa.String(100)),
        sa.Column('description', sa.Text),
        sa.Column('recommendation', sa.Text),
        sa.Column('references', sa.JSON, default=[]),
        sa.Column('tags', sa.JSON, default=[]),
        sa.Column('cwe_ids', sa.JSON, default=[]),
        sa.Column('mitre_attack_ids', sa.JSON, default=[]),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, onupdate=sa.func.now()),
    )
    op.create_index('ix_vulns_severity', 'vulnerabilities', ['severity'])
    op.create_index('ix_vulns_source', 'vulnerabilities', ['source'])
    
    # Audit Log table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id')),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id')),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(50)),
        sa.Column('resource_id', sa.String(36)),
        sa.Column('details', sa.JSON, default={}),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.String(255)),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_audit_organization', 'audit_logs', ['organization_id'])
    op.create_index('ix_audit_user', 'audit_logs', ['user_id'])
    op.create_index('ix_audit_created', 'audit_logs', ['created_at'])


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table('audit_logs')
    op.drop_table('vulnerabilities')
    op.drop_table('scan_findings')
    op.drop_table('scans')
    op.drop_table('approval_rules')
    op.drop_table('approval_requests')
    op.drop_table('incidents')
    op.drop_table('alerts')
    op.drop_table('security_events')
    op.drop_table('agents')
    op.drop_table('api_keys')
    op.drop_table('users')
    op.drop_table('organizations')
'''


# =============================================================================
# MIGRATION RUNNER
# =============================================================================

import os
import sys
from pathlib import Path


def setup_migrations(project_root: str = None):
    """
    Set up Alembic migrations directory structure.
    
    Creates:
    - alembic.ini
    - migrations/env.py
    - migrations/versions/001_initial_schema.py
    """
    root = Path(project_root or os.getcwd())
    
    # Create alembic.ini
    alembic_ini = root / "alembic.ini"
    if not alembic_ini.exists():
        alembic_ini.write_text(ALEMBIC_INI)
        print(f"Created {alembic_ini}")
    
    # Create migrations directory
    migrations_dir = root / "migrations"
    migrations_dir.mkdir(exist_ok=True)
    
    versions_dir = migrations_dir / "versions"
    versions_dir.mkdir(exist_ok=True)
    
    # Create env.py
    env_py = migrations_dir / "env.py"
    if not env_py.exists():
        env_py.write_text(ENV_PY)
        print(f"Created {env_py}")
    
    # Create script.py.mako template
    script_mako = migrations_dir / "script.py.mako"
    if not script_mako.exists():
        script_mako.write_text('''"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

revision: str = ${repr(up_revision)}
down_revision: Union[str, None] = ${repr(down_revision)}
branch_labels: Union[str, Sequence[str], None] = ${repr(branch_labels)}
depends_on: Union[str, Sequence[str], None] = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
''')
        print(f"Created {script_mako}")
    
    # Create initial migration
    initial_migration = versions_dir / "001_initial_schema.py"
    if not initial_migration.exists():
        initial_migration.write_text(INITIAL_MIGRATION)
        print(f"Created {initial_migration}")
    
    print("\nMigrations setup complete!")
    print("\nTo run migrations:")
    print("  alembic upgrade head")
    print("\nTo create a new migration:")
    print("  alembic revision --autogenerate -m 'description'")


def run_migrations():
    """Run pending migrations."""
    try:
        from alembic.config import Config
        from alembic import command
        
        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head")
        print("Migrations completed successfully!")
    except Exception as e:
        print(f"Migration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Database migration management")
    parser.add_argument("command", choices=["setup", "run", "status"])
    parser.add_argument("--project-root", help="Project root directory")
    
    args = parser.parse_args()
    
    if args.command == "setup":
        setup_migrations(args.project_root)
    elif args.command == "run":
        run_migrations()
    elif args.command == "status":
        from alembic.config import Config
        from alembic import command
        alembic_cfg = Config("alembic.ini")
        command.current(alembic_cfg)
