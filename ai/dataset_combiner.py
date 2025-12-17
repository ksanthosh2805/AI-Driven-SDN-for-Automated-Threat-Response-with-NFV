import pandas as pd

files = [
    "datasets/CICIDS2017/Monday-WorkingHours.pcap_ISCX.csv",
    "datasets/CICIDS2017/Tuesday-WorkingHours.pcap_ISCX.csv",
    "datasets/CICIDS2017/Wednesday-workingHours.pcap_ISCX.csv",
    "datasets/CICIDS2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "datasets/CICIDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

dfs = [pd.read_csv(f) for f in files]
df = pd.concat(dfs, ignore_index=True)

# Keep only columns your pipeline expects; map names
df = df.rename(columns={
    "Flow Duration": "duration_sec",
    "Total Fwd Packets": "packets_total",
    "Total Length of Fwd Packets": "bytes_total",
    "Fwd Packet Length Mean": "avg_packet_size",
    "Fwd IAT Mean": "packets_per_sec",   # or another timing-based feature
    # set src_port, dst_port and bytes_per_sec from corresponding columns
    "Source Port": "src_port",
    "Destination Port": "dst_port",
    "Label": "label",
})

df.to_csv("training_dataset.csv", index=False)
