#!/usr/bin/env python3
"""
Real-time Performance Monitoring Dashboard
Displays system metrics, threat statistics, and network status
"""

import time
import requests
from datetime import datetime
import os
import json


class PerformanceDashboard:
    """Real-time monitoring dashboard"""

    def __init__(self):
        self.ai_api_url = 'http://localhost:5000'
        self.stats = {
            'predictions_made': 0,
            'threats_detected': 0,
            'hosts_quarantined': 0,
            'uptime': 0
        }
        self.start_time = time.time()

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')

    def get_ai_stats(self):
        """Fetch stats from AI API (optional)"""
        try:
            response = requests.get(f"{self.ai_api_url}/info", timeout=2)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return {}

    def get_controller_stats(self):
        """Read latest controller stats snapshot written by controller"""
        try:
            with open("/tmp/ai_sdn/controller_stats.json") as f:
                return json.load(f)
        except Exception:
            return {"host_zones": {}, "flow_stats_count": 0}

    def display_header(self):
        """Display dashboard header"""
        print("=" * 80)
        print(" " * 20 + "AI-SDN SECURITY MONITORING DASHBOARD")
        print("=" * 80)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"System Uptime: {int(time.time() - self.start_time)}s")
        print("=" * 80)

    def display_system_status(self):
        """Display system component status"""
        print("\n📊 SYSTEM STATUS")
        print("-" * 80)

        # Check AI API
        try:
            response = requests.get(f"{self.ai_api_url}/health", timeout=1)
            ai_status = "🟢 ONLINE" if response.status_code == 200 else "🔴 OFFLINE"
        except Exception:
            ai_status = "🔴 OFFLINE"

        print(f"  AI Detection API:     {ai_status}")
        print(f"  SDN Controller:       🟢 ONLINE (assumed)")
        print(f"  VNF Services:         🟢 ONLINE (assumed)")

    def display_threat_stats(self):
        """Display threat detection statistics"""
        ctrl = self.get_controller_stats()
        total_flows = ctrl.get("flow_stats_count", 0)

        print("\n🛡️  THREAT DETECTION STATISTICS")
        print("-" * 80)
        print(f"  Total Predictions:    {self.stats['predictions_made']}")
        print(f"  Tracked Flows:        {total_flows}")
        print(f"  Threats Detected:     {self.stats['threats_detected']}")
        print(f"  Hosts Quarantined:    {self.stats['hosts_quarantined']}")

        if self.stats['predictions_made'] > 0:
            threat_rate = (
                self.stats['threats_detected']
                / self.stats['predictions_made']
                * 100
            )
            print(f"  Threat Rate:          {threat_rate:.2f}%")

    def display_network_zones(self):
        """Display micro-segmentation zones"""
        ctrl = self.get_controller_stats()
        # Default structure, then update with real host_zones
        zones = {"trusted": [], "monitored": [], "quarantine": []}
        zones.update(ctrl.get("host_zones", {}))

        print("\n🔐 MICRO-SEGMENTATION ZONES")
        print("-" * 80)

        print("  Trusted (VLAN 100):")
        if zones.get("trusted"):
            for ip in zones["trusted"]:
                print(f"    - {ip}")
        else:
            print("    (empty)")

        print("  Monitored (VLAN 200):")
        if zones.get("monitored"):
            for ip in zones["monitored"]:
                print(f"    - {ip}")
        else:
            print("    (empty)")

        print("  Quarantine (VLAN 999):")
        if zones.get("quarantine"):
            for ip in zones["quarantine"]:
                print(f"    - {ip}")
        else:
            print("    (empty)")

    def display_recent_events(self):
        """Display recent security events (placeholder)"""
        print("\n📋 RECENT EVENTS")
        print("-" * 80)

        # For now, still static examples; could be wired to a log file later
        events = [
            "[12:34:56] Flow analyzed: 192.168.1.10 -> 192.168.1.20 (BENIGN)",
            "[12:35:12] Threat detected: 192.168.1.10 -> 192.168.1.20 (DDoS)",
            "[12:35:13] Host quarantined: 192.168.1.10"
        ]

        for event in events[-5:]:
            print(f"  {event}")

    def display_footer(self):
        """Display dashboard footer"""
        print("\n" + "=" * 80)
        print("Press Ctrl+C to exit")
        print("=" * 80)

    def run(self, refresh_interval=5):
        """Run dashboard with periodic updates"""
        print("Starting dashboard...")

        try:
            while True:
                self.clear_screen()
                self.display_header()
                self.display_system_status()
                self.display_threat_stats()
                self.display_network_zones()
                self.display_recent_events()
                self.display_footer()

                # Example local counter update (increment predictions count)
                self.stats['predictions_made'] += 1

                time.sleep(refresh_interval)

        except KeyboardInterrupt:
            print("\n\nDashboard stopped.")


def main():
    dashboard = PerformanceDashboard()
    dashboard.run(refresh_interval=3)


if __name__ == '__main__':
    main()
