#!/usr/bin/env python3
"""
Flow Data Collector for AI Training
Collects network flow statistics from Open vSwitch
Exports to CSV format for ML training
"""
import json
import subprocess
import time
import pandas as pd
from datetime import datetime
import sys
import csv

class FlowCollector:
    """
    Collects network flow data from OVS switches
    Extracts features suitable for ML anomaly detection
    """
    
    def __init__(self, switch_name='s1', output_file='flow_data.csv'):
        self.switch_name = switch_name
        self.output_file = output_file
        self.flows = []
        
        # Initialize CSV file with headers
        self.headers = [
            'timestamp',
            'src_ip',
            'dst_ip',
            'src_port',
            'dst_port',
            'protocol',
            'duration_sec',
            'packets_total',
            'bytes_total',
            'packets_per_sec',
            'bytes_per_sec',
            'avg_packet_size',
            'tcp_flags',
            'label'  # Will be set manually during training data collection
        ]
        
        # Create file if doesn't exist
        try:
            with open(self.output_file, 'x', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(self.headers)
        except FileExistsError:
            pass
    
    def get_ovs_flows(self):
        """
        Step 18: Implement Flow Collector
        Execute ovs-ofctl command to dump flows
        Returns list of flow dictionaries
        """
        try:
            cmd = f"sudo ovs-ofctl dump-flows {self.switch_name} -O OpenFlow13"
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                check=True
            )
            
            return self.parse_ovs_output(result.stdout)
        
        except subprocess.CalledProcessError as e:
            print(f"Error executing OVS command: {e}")
            return []
    
    def parse_ovs_output(self, output):
        """
        Parse OVS flow output into structured data
        Extract relevant features for ML
        """
        flows = []
        
        for line in output.strip().split('\n'):
            if 'cookie' not in line:
                continue
            
            flow_data = {}
            
            try:
                # Extract duration
                if 'duration' in line:
                    duration = line.split('duration=')[1].split('s')[0]
                    flow_data['duration_sec'] = float(duration)
                
                # Extract packet count
                if 'n_packets' in line:
                    packets = line.split('n_packets=')[1].split(',')[0]
                    flow_data['packets_total'] = int(packets)
                
                # Extract byte count
                if 'n_bytes' in line:
                    bytes_count = line.split('n_bytes=')[1].split(',')[0]
                    flow_data['bytes_total'] = int(bytes_count)
                
                # Extract IP addresses
                if 'nw_src=' in line:
                    src_ip = line.split('nw_src=')[1].split(',')[0]
                    flow_data['src_ip'] = src_ip
                
                if 'nw_dst=' in line:
                    dst_ip = line.split('nw_dst=')[1].split(',')[0]
                    flow_data['dst_ip'] = dst_ip
                
                # Extract ports
                if 'tp_src=' in line:
                    src_port = line.split('tp_src=')[1].split(',')[0]
                    flow_data['src_port'] = int(src_port)
                
                if 'tp_dst=' in line:
                    dst_port = line.split('tp_dst=')[1].split(',')[0]
                    flow_data['dst_port'] = int(dst_port)
                
                # Extract protocol
                if 'tcp' in line.lower():
                    flow_data['protocol'] = 'TCP'
                elif 'udp' in line.lower():
                    flow_data['protocol'] = 'UDP'
                elif 'icmp' in line.lower():
                    flow_data['protocol'] = 'ICMP'
                else:
                    flow_data['protocol'] = 'OTHER'
                
                # Calculate derived features
                if flow_data.get('duration_sec', 0) > 0:
                    flow_data['packets_per_sec'] = \
                        flow_data.get('packets_total', 0) / flow_data['duration_sec']
                    flow_data['bytes_per_sec'] = \
                        flow_data.get('bytes_total', 0) / flow_data['duration_sec']
                else:
                    flow_data['packets_per_sec'] = 0
                    flow_data['bytes_per_sec'] = 0
                
                if flow_data.get('packets_total', 0) > 0:
                    flow_data['avg_packet_size'] = \
                        flow_data.get('bytes_total', 0) / flow_data['packets_total']
                else:
                    flow_data['avg_packet_size'] = 0
                
                # Add timestamp
                flow_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Default label (will be updated manually)
                flow_data['label'] = 'unknown'
                
                # TCP flags (simplified)
                flow_data['tcp_flags'] = 'NONE'
                
                flows.append(flow_data)
            
            except Exception as e:
                print(f"Error parsing flow line: {e}")
                continue
        
        return flows
    
    def collect_and_save(self, label='benign', duration=60, interval=5):
        """
        Collect flows for specified duration
        label: 'benign', 'ddos', 'port_scan', etc.
        duration: Total collection time in seconds
        interval: Time between collections
        """
        print(f"Collecting {label} traffic for {duration} seconds...")
        
        start_time = time.time()
        collected_count = 0
        
        while (time.time() - start_time) < duration:
            flows = self.get_ovs_flows()
            
            # Save flows to CSV
            with open(self.output_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.headers)
                
                for flow in flows:
                    # Update label
                    flow['label'] = label
                    
                    # Fill missing fields with defaults
                    for header in self.headers:
                        if header not in flow:
                            flow[header] = 'N/A'
                    
                    writer.writerow(flow)
                    collected_count += 1
            
            print(f"Collected {len(flows)} flows. Total: {collected_count}")
            time.sleep(interval)
        
        print(f"Collection complete. Total flows: {collected_count}")
    
    def display_statistics(self):
        """Display statistics about collected data"""
        try:
            df = pd.read_csv(self.output_file)
            
            print("\n=== Flow Collection Statistics ===")
            print(f"Total Flows: {len(df)}")
            print(f"\nLabel Distribution:")
            print(df['label'].value_counts())
            print(f"\nProtocol Distribution:")
            print(df['protocol'].value_counts())
            print(f"\nBasic Statistics:")
            print(df[['packets_total', 'bytes_total', 'duration_sec']].describe())
        
        except FileNotFoundError:
            print(f"File {self.output_file} not found")
        except Exception as e:
            print(f"Error displaying statistics: {e}")

def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        print("Usage: python3 flow_collector.py <label> [duration] [interval]")
        print("Example: python3 flow_collector.py benign 120 5")
        print("Labels: benign, ddos, port_scan, brute_force, etc.")
        sys.exit(1)
    
    label = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    interval = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    
    collector = FlowCollector(switch_name='s1', output_file='network_flows.csv')
    
    print(f"Starting flow collection: label={label}, duration={duration}s")
    print("Press Ctrl+C to stop early\n")
    
    try:
        collector.collect_and_save(label=label, duration=duration, interval=interval)
        collector.display_statistics()
    except KeyboardInterrupt:
        print("\nCollection interrupted by user")
        collector.display_statistics()

if __name__ == '__main__':
    main()