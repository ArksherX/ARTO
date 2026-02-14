#!/usr/bin/env python3
"""
Enterprise Report Generator

Generates daily/weekly/monthly security reports
"""

from datetime import datetime, timedelta
from pathlib import Path
import json
import pandas as pd
from typing import List, Dict, Optional
import matplotlib.pyplot as plt
import seaborn as sns


class EnterpriseReportGenerator:
    """
    Generate comprehensive security reports
    """
    
    def __init__(self, log_dir: str = "flight_logs"):
        self.log_dir = Path(log_dir)
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_daily_report(self, date: Optional[datetime] = None) -> Dict:
        """
        Generate daily security report
        
        Args:
            date: Date to generate report for (default: today)
        
        Returns:
            Report dictionary
        """
        if date is None:
            date = datetime.now()
        
        # Load logs for the day
        logs = self._load_logs_for_date(date)
        
        if not logs:
            return {
                'error': 'No logs found for this date',
                'date': date.isoformat()
            }
        
        # Generate report sections
        report = {
            'generated_at': datetime.now().isoformat(),
            'report_date': date.strftime('%Y-%m-%d'),
            'report_type': 'daily',
            
            # Executive Summary
            'executive_summary': self._generate_executive_summary(logs),
            
            # Security Metrics
            'security_metrics': self._generate_security_metrics(logs),
            
            # Agent Activity
            'agent_activity': self._generate_agent_activity(logs),
            
            # Threat Analysis
            'threat_analysis': self._generate_threat_analysis(logs),
            
            # Top Incidents
            'top_incidents': self._get_top_incidents(logs, limit=10),
            
            # Recommendations
            'recommendations': self._generate_recommendations(logs)
        }
        
        # Save report
        report_file = self.reports_dir / f"daily_report_{date.strftime('%Y%m%d')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate visualizations
        self._generate_visualizations(logs, date)
        
        return report
    
    def generate_pdf_report(self, date: Optional[datetime] = None) -> Path:
        """
        Generate PDF report with visualizations
        
        Requires: reportlab
        """
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
        
        if date is None:
            date = datetime.now()
        
        # Generate JSON report first
        report = self.generate_daily_report(date)
        
        if 'error' in report:
            raise ValueError(report['error'])
        
        # Create PDF
        pdf_file = self.reports_dir / f"daily_report_{date.strftime('%Y%m%d')}.pdf"
        doc = SimpleDocTemplate(str(pdf_file), pagesize=letter)
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title = Paragraph(f"<b>VerityFlux Security Report</b><br/>{date.strftime('%B %d, %Y')}", 
                         styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 20))
        
        # Executive Summary
        exec_summary = report['executive_summary']
        elements.append(Paragraph("<b>Executive Summary</b>", styles['Heading2']))
        elements.append(Paragraph(f"Total Actions: {exec_summary['total_actions']}", styles['Normal']))
        elements.append(Paragraph(f"Attacks Blocked: {exec_summary['attacks_blocked']}", styles['Normal']))
        elements.append(Paragraph(f"Detection Rate: {exec_summary['detection_rate']:.1f}%", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Security Metrics Table
        elements.append(Paragraph("<b>Security Metrics</b>", styles['Heading2']))
        
        metrics = report['security_metrics']
        metrics_data = [
            ['Metric', 'Value'],
            ['Avg Risk Score', f"{metrics['avg_risk_score']:.1f}/100"],
            ['Deceptions Detected', str(metrics['deceptions_detected'])],
            ['Vulnerability Alerts', str(metrics['vulnerability_alerts'])],
            ['Critical Incidents', str(metrics['critical_incidents'])]
        ]
        
        metrics_table = Table(metrics_data)
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(metrics_table)
        elements.append(Spacer(1, 20))
        
        # Add visualizations
        risk_chart = self.reports_dir / f"risk_distribution_{date.strftime('%Y%m%d')}.png"
        if risk_chart.exists():
            elements.append(Paragraph("<b>Risk Distribution</b>", styles['Heading2']))
            elements.append(Image(str(risk_chart), width=400, height=300))
            elements.append(Spacer(1, 20))
        
        # Top Incidents
        elements.append(Paragraph("<b>Top Security Incidents</b>", styles['Heading2']))
        
        for i, incident in enumerate(report['top_incidents'][:5], 1):
            elements.append(Paragraph(
                f"<b>#{i}:</b> Agent {incident['agent_id']} - "
                f"Risk {incident['risk_score']:.0f}/100 - "
                f"{incident['tier']}<br/>"
                f"<i>{incident['reasoning']}</i>",
                styles['Normal']
            ))
            elements.append(Spacer(1, 10))
        
        # Build PDF
        doc.build(elements)
        
        return pdf_file
    
    def _load_logs_for_date(self, date: datetime) -> List[Dict]:
        """Load all logs for a specific date"""
        logs = []
        
        for log_file in self.log_dir.glob("*.jsonl"):
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        log = json.loads(line)
                        log_date = datetime.fromisoformat(log['timestamp']).date()
                        
                        if log_date == date.date():
                            logs.append(log)
                    except:
                        pass
        
        return logs
    
    def _generate_executive_summary(self, logs: List[Dict]) -> Dict:
        """Generate executive summary"""
        total_actions = len(logs)
        attacks_blocked = sum(1 for log in logs if log['firewall_decision']['action'] in ['block', 'require_approval'])
        
        return {
            'total_actions': total_actions,
            'attacks_blocked': attacks_blocked,
            'detection_rate': (attacks_blocked / max(total_actions, 1)) * 100,
            'unique_agents': len(set(log['agent_id'] for log in logs)),
            'status': 'SECURE' if attacks_blocked == 0 else 'ACTIVE THREATS DETECTED'
        }
    
    def _generate_security_metrics(self, logs: List[Dict]) -> Dict:
        """Generate detailed security metrics"""
        risk_scores = [log['firewall_decision']['risk_score'] for log in logs]
        
        return {
            'avg_risk_score': np.mean(risk_scores) if risk_scores else 0,
            'max_risk_score': max(risk_scores) if risk_scores else 0,
            'deceptions_detected': sum(1 for log in logs if log['enterprise_analysis']['deception_detected']),
            'vulnerability_alerts': sum(log['enterprise_analysis']['vulnerability_matches'] for log in logs),
            'critical_incidents': sum(1 for log in logs if log['firewall_decision']['tier'] == 'CRITICAL')
        }
    
    def _generate_agent_activity(self, logs: List[Dict]) -> Dict:
        """Generate agent activity breakdown"""
        agents = {}
        
        for log in logs:
            agent_id = log['agent_id']
            if agent_id not in agents:
                agents[agent_id] = {
                    'total_actions': 0,
                    'blocked': 0,
                    'avg_risk': []
                }
            
            agents[agent_id]['total_actions'] += 1
            if log['firewall_decision']['action'] in ['block', 'require_approval']:
                agents[agent_id]['blocked'] += 1
            agents[agent_id]['avg_risk'].append(log['firewall_decision']['risk_score'])
        
        # Calculate averages
        for agent_id in agents:
            agents[agent_id]['avg_risk_score'] = np.mean(agents[agent_id]['avg_risk'])
            del agents[agent_id]['avg_risk']
        
        return agents
    
    def _generate_threat_analysis(self, logs: List[Dict]) -> Dict:
        """Analyze threat patterns"""
        threat_types = {}
        
        for log in logs:
            for violation in log['enterprise_analysis']['violations']:
                # Extract threat type (first few words)
                threat_type = ' '.join(violation.split()[:3])
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        return {
            'top_threats': sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:10],
            'total_threat_types': len(threat_types)
        }
    
    def _get_top_incidents(self, logs: List[Dict], limit: int = 10) -> List[Dict]:
        """Get top security incidents by risk score"""
        sorted_logs = sorted(logs, key=lambda x: x['firewall_decision']['risk_score'], reverse=True)
        
        incidents = []
        for log in sorted_logs[:limit]:
            incidents.append({
                'timestamp': log['timestamp'],
                'agent_id': log['agent_id'],
                'tool': log['tool_name'],
                'risk_score': log['firewall_decision']['risk_score'],
                'tier': log['firewall_decision']['tier'],
                'decision': log['firewall_decision']['action'],
                'reasoning': log['firewall_decision']['reasoning'],
                'violations': log['enterprise_analysis']['violations']
            })
        
        return incidents
    
    def _generate_recommendations(self, logs: List[Dict]) -> List[str]:
        """Generate security recommendations based on logs"""
        recommendations = []
        
        # Analyze patterns
        high_risk_agents = [log['agent_id'] for log in logs if log['firewall_decision']['risk_score'] > 70]
        
        if high_risk_agents:
            most_risky = max(set(high_risk_agents), key=high_risk_agents.count)
            recommendations.append(f"⚠️ Agent '{most_risky}' has multiple high-risk actions - recommend audit")
        
        # Check for repeated deceptions
        deceptive_agents = [log['agent_id'] for log in logs if log['enterprise_analysis']['deception_detected']]
        if len(deceptive_agents) > 5:
            recommendations.append("🚨 High deception rate detected - enable stricter intent validation")
        
        # Check SQL injection attempts
        sql_attacks = sum(1 for log in logs if log['enterprise_analysis']['risk_breakdown'].get('sql_validation', 0) > 70)
        if sql_attacks > 0:
            recommendations.append(f"🔒 {sql_attacks} SQL injection attempts detected - review database access policies")
        
        # Check credential access
        cred_attempts = sum(1 for log in logs if log['enterprise_analysis']['risk_breakdown'].get('credential_access', 0) > 50)
        if cred_attempts > 0:
            recommendations.append(f"🔑 {cred_attempts} credential access attempts - rotate sensitive keys")
        
        # Generic recommendations
        if not recommendations:
            recommendations.append("✅ No immediate security concerns detected")
            recommendations.append("💡 Continue monitoring agent behavior patterns")
        
        return recommendations
    
    def _generate_visualizations(self, logs: List[Dict], date: datetime) -> None:
        """Generate visualization charts"""
        
        # Risk distribution chart
        risk_scores = [log['firewall_decision']['risk_score'] for log in logs]
        
        plt.figure(figsize=(10, 6))
        plt.hist(risk_scores, bins=20, color='steelblue', edgecolor='black')
        plt.xlabel('Risk Score')
        plt.ylabel('Frequency')
        plt.title(f'Risk Score Distribution - {date.strftime("%Y-%m-%d")}')
        plt.grid(True, alpha=0.3)
        
        chart_file = self.reports_dir / f"risk_distribution_{date.strftime('%Y%m%d')}.png"
        plt.savefig(chart_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        # Timeline chart
        df = pd.DataFrame(logs)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.set_index('timestamp')
        
        # Resample by hour
        hourly_counts = df.resample('H').size()
        
        plt.figure(figsize=(12, 6))
        hourly_counts.plot(kind='bar', color='coral')
        plt.xlabel('Hour')
        plt.ylabel('Actions')
        plt.title(f'Agent Activity Timeline - {date.strftime("%Y-%m-%d")}')
        plt.xticks(rotation=45)
        plt.grid(True, alpha=0.3)
        
        timeline_file = self.reports_dir / f"activity_timeline_{date.strftime('%Y%m%d')}.png"
        plt.savefig(timeline_file, dpi=300, bbox_inches='tight')
        plt.close()


# CLI Tool
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate VerityFlux Security Reports')
    parser.add_argument('--date', help='Date (YYYY-MM-DD)', default=None)
    parser.add_argument('--format', choices=['json', 'pdf', 'both'], default='json')
    
    args = parser.parse_args()
    
    # Parse date
    if args.date:
        report_date = datetime.strptime(args.date, '%Y-%m-%d')
    else:
        report_date = datetime.now()
    
    # Generate report
    generator = EnterpriseReportGenerator()
    
    print(f"🔍 Generating report for {report_date.strftime('%Y-%m-%d')}...")
    
    if args.format in ['json', 'both']:
        report = generator.generate_daily_report(report_date)
        
        if 'error' in report:
            print(f"❌ Error: {report['error']}")
            return 1
        
        print(f"✅ JSON report generated")
        print(f"\n📊 Executive Summary:")
        print(f"  • Total Actions: {report['executive_summary']['total_actions']}")
        print(f"  • Attacks Blocked: {report['executive_summary']['attacks_blocked']}")
        print(f"  • Detection Rate: {report['executive_summary']['detection_rate']:.1f}%")
        print(f"  • Status: {report['executive_summary']['status']}")
    
    if args.format in ['pdf', 'both']:
        try:
            pdf_file = generator.generate_pdf_report(report_date)
            print(f"✅ PDF report generated: {pdf_file}")
        except Exception as e:
            print(f"⚠️ PDF generation failed: {e}")
            print("   Install reportlab: pip install reportlab")
    
    print(f"\n📁 Reports saved to: reports/")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
