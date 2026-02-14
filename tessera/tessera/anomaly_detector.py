#!/usr/bin/env python3
"""
Behavioral Anomaly Detection
Detects suspicious patterns in agent behavior
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
import statistics

@dataclass
class AnomalyAlert:
    agent_id: str
    anomaly_type: str
    severity: str
    description: str
    timestamp: datetime
    metrics: Dict

class AnomalyDetector:
    """
    Detects behavioral anomalies in agent activity
    Uses statistical baselines and rule-based detection
    """
    
    def __init__(self, persistence):
        self.persistence = persistence
        self.thresholds = {
            'request_spike_multiplier': 10,  # 10x normal rate
            'response_time_stddev': 3,        # 3 standard deviations
            'failure_rate_threshold': 0.5,    # 50% failures
            'burst_window_seconds': 60,
            'burst_limit': 100
        }
    
    def check_for_anomalies(self, agent_id: str, tool: str) -> List[AnomalyAlert]:
        """
        Check for behavioral anomalies
        
        Returns list of alerts (empty if no anomalies)
        """
        alerts = []
        
        # Get agent's baseline behavior
        baseline = self.persistence.get_agent_baseline(agent_id, lookback_hours=24)
        
        if baseline['request_count'] < 10:
            # Not enough data for anomaly detection
            return alerts
        
        # Check 1: Request rate spike
        current_rate = self._get_current_request_rate(agent_id)
        normal_rate = baseline['request_count'] / 24  # Per hour
        
        if current_rate > normal_rate * self.thresholds['request_spike_multiplier']:
            alerts.append(AnomalyAlert(
                agent_id=agent_id,
                anomaly_type='REQUEST_SPIKE',
                severity='high',
                description=f"Request rate {current_rate:.0f}/hr vs normal {normal_rate:.0f}/hr",
                timestamp=datetime.now(),
                metrics={
                    'current_rate': current_rate,
                    'normal_rate': normal_rate,
                    'multiplier': current_rate / normal_rate
                }
            ))
        
        # Check 2: Response time anomaly
        recent_response_times = self._get_recent_response_times(agent_id, minutes=5)
        if recent_response_times and baseline['avg_response_time'] > 0:
            avg_recent = statistics.mean(recent_response_times)
            threshold = (
                baseline['avg_response_time'] + 
                self.thresholds['response_time_stddev'] * baseline['stddev_response_time']
            )
            
            if avg_recent > threshold:
                alerts.append(AnomalyAlert(
                    agent_id=agent_id,
                    anomaly_type='SLOW_RESPONSE',
                    severity='medium',
                    description=f"Response time {avg_recent:.0f}ms vs baseline {baseline['avg_response_time']:.0f}ms",
                    timestamp=datetime.now(),
                    metrics={
                        'current_avg': avg_recent,
                        'baseline_avg': baseline['avg_response_time'],
                        'baseline_stddev': baseline['stddev_response_time']
                    }
                ))
        
        # Check 3: High failure rate
        recent_failures = self._get_recent_failures(agent_id, minutes=5)
        recent_total = len(recent_response_times) if recent_response_times else 0
        
        if recent_total > 0:
            failure_rate = recent_failures / recent_total
            if failure_rate > self.thresholds['failure_rate_threshold']:
                alerts.append(AnomalyAlert(
                    agent_id=agent_id,
                    anomaly_type='HIGH_FAILURE_RATE',
                    severity='high',
                    description=f"Failure rate {failure_rate:.1%} in last 5 minutes",
                    timestamp=datetime.now(),
                    metrics={
                        'failure_rate': failure_rate,
                        'failures': recent_failures,
                        'total_requests': recent_total
                    }
                ))
        
        # Check 4: Burst detection (too many requests in short window)
        burst_count = self._get_burst_count(agent_id, seconds=60)
        if burst_count > self.thresholds['burst_limit']:
            alerts.append(AnomalyAlert(
                agent_id=agent_id,
                anomaly_type='REQUEST_BURST',
                severity='critical',
                description=f"{burst_count} requests in 60 seconds (limit: {self.thresholds['burst_limit']})",
                timestamp=datetime.now(),
                metrics={
                    'burst_count': burst_count,
                    'window_seconds': 60,
                    'limit': self.thresholds['burst_limit']
                }
            ))
        
        return alerts
    
    def _get_current_request_rate(self, agent_id: str) -> float:
        """Get current request rate (requests per hour)"""
        # Query last hour of activity
        conn = self.persistence.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT COUNT(*) 
                FROM behavioral_metrics
                WHERE agent_id = %s 
                  AND timestamp > NOW() - INTERVAL '1 hour'
            """, (agent_id,))
            
            count = cur.fetchone()[0]
            return count  # Already per hour
        finally:
            self.persistence.pg_pool.putconn(conn)
    
    def _get_recent_response_times(self, agent_id: str, minutes: int) -> List[int]:
        """Get response times from last N minutes"""
        conn = self.persistence.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT response_time_ms
                FROM behavioral_metrics
                WHERE agent_id = %s 
                  AND timestamp > NOW() - INTERVAL '%s minutes'
                  AND response_time_ms IS NOT NULL
            """, (agent_id, minutes))
            
            return [row[0] for row in cur.fetchall()]
        finally:
            self.persistence.pg_pool.putconn(conn)
    
    def _get_recent_failures(self, agent_id: str, minutes: int) -> int:
        """Count failures in last N minutes"""
        conn = self.persistence.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT COUNT(*)
                FROM behavioral_metrics
                WHERE agent_id = %s 
                  AND timestamp > NOW() - INTERVAL '%s minutes'
                  AND success = FALSE
            """, (agent_id, minutes))
            
            return cur.fetchone()[0]
        finally:
            self.persistence.pg_pool.putconn(conn)
    
    def _get_burst_count(self, agent_id: str, seconds: int) -> int:
        """Count requests in last N seconds"""
        conn = self.persistence.pg_pool.getconn()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT COUNT(*)
                FROM behavioral_metrics
                WHERE agent_id = %s 
                  AND timestamp > NOW() - INTERVAL '%s seconds'
            """, (agent_id, seconds))
            
            return cur.fetchone()[0]
        finally:
            self.persistence.pg_pool.putconn(conn)

def get_anomaly_detector(persistence) -> AnomalyDetector:
    """Create anomaly detector with persistence"""
    return AnomalyDetector(persistence)
