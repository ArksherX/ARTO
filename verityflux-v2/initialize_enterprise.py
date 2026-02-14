#!/usr/bin/env python3
"""
Initialize Enterprise VerityFlux

Loads all vulnerability databases and prepares the system
"""

import sys
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from cognitive_firewall import EnhancedCognitiveFirewall
from vulnerability_database import VulnerabilityUpdater
import argparse


def main():
    parser = argparse.ArgumentParser(description='Initialize Enterprise VerityFlux')
    parser.add_argument('--cve-api-key', help='NVD API key (optional, for higher rate limits)')
    parser.add_argument('--auto-update', action='store_true', help='Start auto-update service')
    parser.add_argument('--update-interval', type=int, default=21600, 
                       help='Update interval in seconds (default: 6 hours)')
    
    args = parser.parse_args()
    
    print("="*70)
    print("🛡️  VERITYFLUX ENTERPRISE INITIALIZATION")
    print("="*70)
    
    # Initialize firewall
    print("\n1️⃣  Initializing Enhanced Cognitive Firewall...")
    firewall = EnhancedCognitiveFirewall()
    
    # Load vulnerabilities
    print("\n2️⃣  Loading Vulnerability Database...")
    vuln_count = firewall.load_vulnerabilities(cve_api_key=args.cve_api_key)
    
    if vuln_count == 0:
        print("⚠️  Warning: No vulnerabilities loaded. System will rely on heuristics only.")
    
    # Start auto-updater if requested
    if args.auto_update:
        print("\n3️⃣  Starting Auto-Update Service...")
        updater = VulnerabilityUpdater(
            database=firewall.vuln_db,
            cve_api_key=args.cve_api_key,
            update_interval=args.update_interval
        )
        updater.start()
        print(f"  ✅ Auto-update service started (interval: {args.update_interval}s)")
    
    # Display statistics
    print("\n4️⃣  System Statistics:")
    stats = firewall.get_statistics()
    print(f"  • Total Vulnerabilities: {stats['vulnerability_database']['total_vulnerabilities']}")
    print(f"  • Intent Categories: {stats['intent_analyzer']['known_categories']}")
    print(f"  • False Positive Cache: {stats['intent_analyzer']['false_positive_cache_size']}")
    
    print("\n" + "="*70)
    print("✅ VerityFlux Enterprise Ready!")
    print("="*70)
    
    # Save firewall instance for web UI
    import pickle
    with open('.verityflux_instance.pkl', 'wb') as f:
        pickle.dump(firewall, f)
    
    print("\n💡 Next steps:")
    print("  1. Run web UI: streamlit run web_ui.py")
    print("  2. Run tests: python3 test_enterprise.py")
    print("  3. Check stats: python3 -c 'from initialize_enterprise import *; print(firewall.get_statistics())'")
    
    if args.auto_update:
        print("\n⏰ Auto-update service running in background")
        print("  Press Ctrl+C to stop")
        try:
            import time
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping auto-update service...")
            updater.stop()
            print("✅ Stopped")


if __name__ == "__main__":
    main()
