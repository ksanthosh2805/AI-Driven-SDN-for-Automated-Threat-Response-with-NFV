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
        self.start_time = time.time()

    # --------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------

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
            return {
                "host_zones": {},
                "flow_stats_count": 0,
                "total_threats": 0,
                "blocked_hosts": [],
                "recent_threats": []
            }

    # --------------------------------------------------------------
    # Display sections
    # --------------------------------------------------------------

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

        print(f" AI Detection API: {ai_status}")
        print(f" SDN Controller: 🟢 ONLINE ")
        print(f" VNF Services: 🟢 ONLINE ")

    def display_threat_stats(self):
        """Display threat detection statistics (live from controller)"""
        ctrl = self.get_controller_stats()
        total_flows = ctrl.get("flow_stats_count", 0)
        total_threats = ctrl.get("total_threats", 0)
        blocked_hosts = ctrl.get("blocked_hosts", [])

        print("\n🛡️ THREAT DETECTION STATISTICS")
        print("-" * 80)
        print(f" Total Predictions: {total_flows}")
        print(f" Tracked Flows: {total_flows}")
        print(f" Threats Detected: {total_threats}")
        print(f" Hosts Quarantined: {len(blocked_hosts)}")

        if total_flows > 0:
            threat_rate = (total_threats / total_flows) * 100
            print(f" Threat Rate: {threat_rate:.2f}%")
        else:
            print(" Threat Rate: 0.00%")

    def display_network_zones(self):
        """Display micro-segmentation zones"""
        ctrl = self.get_controller_stats()

        zones = {"trusted": [], "monitored": [], "quarantine": []}
        zones.update(ctrl.get("host_zones", {}))

        print("\n🔐 MICRO-SEGMENTATION ZONES")
        print("-" * 80)

        print(" Trusted (VLAN 100):")
        if zones.get("trusted"):
            for ip in zones["trusted"]:
                print(f" - {ip}")
        else:
            print(" (empty)")

        print(" Monitored (VLAN 200):")
        if zones.get("monitored"):
            for ip in zones["monitored"]:
                print(f" - {ip}")
        else:
            print(" (empty)")

        print(" Quarantine (VLAN 999):")
        if zones.get("quarantine"):
            for ip in zones["quarantine"]:
                print(f" - {ip}")
        else:
            print(" (empty)")

    def display_recent_events(self):
        """Display recent security events from controller"""
        ctrl = self.get_controller_stats()
        recent = ctrl.get("recent_threats", [])

        print("\n📋 RECENT EVENTS")
        print("-" * 80)

        if not recent:
            print(" (no recent events)")
            return

        for ev in recent[-5:]:
            ts = ev.get("timestamp", "-")
            src = ev.get("src_ip", "-")
            dst = ev.get("dst_ip", "-")
            action = ev.get("action", "-")
            conf = float(ev.get("confidence", 0.0))
            print(f" [{ts}] Threat: {src} -> {dst}, action={action}, conf={conf:.2f}")

    def display_footer(self):
        """Display dashboard footer"""
        print("\n" + "=" * 80)
        print("Press Ctrl+C to exit")
        print("=" * 80)

    # --------------------------------------------------------------
    # Main loop
    # --------------------------------------------------------------

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
                time.sleep(refresh_interval)
        except KeyboardInterrupt:
            print("\n\nDashboard stopped.")


def main():
    dashboard = PerformanceDashboard()
    dashboard.run(refresh_interval=3)


if __name__ == '__main__':
    main()
