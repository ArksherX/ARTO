#!/usr/bin/env python3
"""
Vestigia CLI - Command-line interface for all operations
Fixed version with proper argument parsing

Usage:
  python cli.py verify                              # Default ledger
  python cli.py verify demo_production.json         # Positional
  python cli.py --ledger demo.json verify           # Flag before command
  python cli.py verify --ledger demo.json           # Flag after command
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from core.ledger_engine import VestigiaLedger, ActionType, EventStatus, StructuredEvidence
from security.verifier import ProductionVerifier


def get_ledger_path(args) -> str:
    """
    Smart ledger path resolution
    Supports multiple argument styles
    """
    # Priority: command-specific > global flag > default
    if hasattr(args, 'ledger_positional') and args.ledger_positional:
        return args.ledger_positional
    elif hasattr(args, 'ledger_file') and args.ledger_file:
        return args.ledger_file
    else:
        return 'data/vestigia_ledger.json'


def cmd_log(args):
    """Log a new event"""
    ledger = VestigiaLedger(get_ledger_path(args))
    
    # Create evidence
    if args.risk_score or args.mitigation or args.payload:
        evidence = StructuredEvidence(
            summary=args.evidence,
            raw_payload=args.payload,
            risk_score=args.risk_score,
            mitigation=args.mitigation
        )
    else:
        evidence = args.evidence
    
    event = ledger.append_event(
        actor_id=args.actor,
        action_type=args.action,
        status=args.status,
        evidence=evidence
    )
    
    print(f"✅ Event logged: {event.event_id}")


def cmd_verify(args):
    """Verify ledger integrity"""
    ledger_path = get_ledger_path(args)
    witness_path = args.witness if args.witness else 'data/witness.hash'
    
    verifier = ProductionVerifier(ledger_path, witness_path)
    result = verifier.verify_full()
    
    if args.json:
        import json
        print(json.dumps(result.to_dict(), indent=2))
    else:
        result.print_report()
    
    sys.exit(0 if result.is_valid else 1)


def cmd_query(args):
    """Query events"""
    ledger = VestigiaLedger(get_ledger_path(args))
    
    events = ledger.query_events(
        actor_id=args.actor,
        action_type=args.action,
        status=args.status,
        limit=args.limit
    )
    
    print(f"Found {len(events)} events:\n")
    
    for event in events:
        print(f"[{event.timestamp}] {event.event_id}")
        print(f"  Actor: {event.actor_id}")
        print(f"  Action: {event.action_type}")
        print(f"  Status: {event.status}")
        
        evidence = event.get_evidence_structured()
        print(f"  Evidence: {evidence.summary[:60]}...")
        
        if evidence.risk_score:
            print(f"  Risk: {evidence.risk_score}")
        
        print()


def cmd_stats(args):
    """Show ledger statistics"""
    ledger = VestigiaLedger(get_ledger_path(args))
    stats = ledger.get_statistics()
    
    print("\n" + "="*60)
    print("  📊 Ledger Statistics")
    print("="*60 + "\n")
    
    print(f"Total Events: {stats['total_events']}")
    print(f"First Entry: {stats['first_entry']}")
    print(f"Last Entry: {stats['last_entry']}\n")
    
    print("Status Breakdown:")
    for status, count in stats['status_breakdown'].items():
        print(f"  {status}: {count}")
    
    print("\nAction Breakdown:")
    for action, count in stats['action_breakdown'].items():
        print(f"  {action}: {count}")


def cmd_export(args):
    """Export compliance report"""
    ledger = VestigiaLedger(get_ledger_path(args))
    
    path = ledger.export_compliance_report(
        args.output,
        format=args.format
    )
    
    print(f"✅ Report exported to: {path}")


def main():
    """Main CLI entry point with bulletproof argument parsing"""
    
    # Main parser with global options
    parser = argparse.ArgumentParser(
        description="Vestigia - Immutable Observability CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify default ledger
  python cli.py verify
  
  # Verify specific ledger (positional)
  python cli.py verify demo_production.json
  
  # Verify specific ledger (flag)
  python cli.py verify --ledger demo_production.json
  python cli.py --ledger demo.json verify
  
  # Log an event
  python cli.py log agent_001 TOOL_EXECUTION SUCCESS "Description"
  
  # Query events
  python cli.py query --status CRITICAL --limit 50
        """
    )
    
    # Global options (available for all commands)
    parser.add_argument(
        '--ledger',
        dest='ledger_file',
        help='Path to ledger file (default: data/vestigia_ledger.json)'
    )
    parser.add_argument(
        '--witness',
        default='data/witness.hash',
        help='Path to witness file (default: data/witness.hash)'
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(
        dest='command',
        required=True,
        help='Available commands'
    )
    
    # ========================================================================
    # LOG COMMAND
    # ========================================================================
    log_parser = subparsers.add_parser(
        'log',
        help='Log a new event'
    )
    log_parser.add_argument('actor', help='Actor ID')
    log_parser.add_argument('action', help='Action type')
    log_parser.add_argument('status', help='Status (SUCCESS/BLOCKED/CRITICAL)')
    log_parser.add_argument('evidence', help='Evidence summary')
    log_parser.add_argument('--payload', help='Raw payload')
    log_parser.add_argument('--risk-score', type=float, help='Risk score (0-1)')
    log_parser.add_argument('--mitigation', help='Mitigation taken')
    log_parser.set_defaults(func=cmd_log)
    
    # ========================================================================
    # VERIFY COMMAND
    # ========================================================================
    verify_parser = subparsers.add_parser(
        'verify',
        help='Verify ledger integrity'
    )
    # Support positional ledger path for verify
    verify_parser.add_argument(
        'ledger_positional',
        nargs='?',
        help='Ledger file path (alternative to --ledger flag)'
    )
    verify_parser.add_argument(
        '--json',
        action='store_true',
        help='Output as JSON'
    )
    verify_parser.set_defaults(func=cmd_verify)
    
    # ========================================================================
    # QUERY COMMAND
    # ========================================================================
    query_parser = subparsers.add_parser(
        'query',
        help='Query events'
    )
    query_parser.add_argument('--actor', help='Filter by actor')
    query_parser.add_argument('--action', help='Filter by action')
    query_parser.add_argument('--status', help='Filter by status')
    query_parser.add_argument('--limit', type=int, default=20, help='Max results')
    query_parser.set_defaults(func=cmd_query)
    
    # ========================================================================
    # STATS COMMAND
    # ========================================================================
    stats_parser = subparsers.add_parser(
        'stats',
        help='Show ledger statistics'
    )
    stats_parser.set_defaults(func=cmd_stats)
    
    # ========================================================================
    # EXPORT COMMAND
    # ========================================================================
    export_parser = subparsers.add_parser(
        'export',
        help='Export compliance report'
    )
    export_parser.add_argument('output', help='Output file path')
    export_parser.add_argument(
        '--format',
        choices=['json', 'csv'],
        default='json',
        help='Export format'
    )
    export_parser.set_defaults(func=cmd_export)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute command
    try:
        args.func(args)
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
