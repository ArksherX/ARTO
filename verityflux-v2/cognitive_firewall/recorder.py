import json
import os
from datetime import datetime

class FlightRecorder:
    def __init__(self, log_file="logs/security_events.json"):
        self.log_file = log_file
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                json.dump([], f)

    def record_event(self, agent_state, firewall_decision):
        event = {
            "timestamp": datetime.now().isoformat(),
            "agent_state": agent_state,
            "firewall_decision": firewall_decision
        }
        logs = self.get_all_events()
        logs.append(event)
        
        # Keep only last 1000 events to save space
        if len(logs) > 1000:
            logs = logs[-1000:]
            
        with open(self.log_file, 'w') as f:
            json.dump(logs, f, indent=2)

    def get_all_events(self):
        if not os.path.exists(self.log_file):
            return []
        try:
            with open(self.log_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
