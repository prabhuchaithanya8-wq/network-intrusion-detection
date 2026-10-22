from pathlib import Path
import numpy as np
import pandas as pd

rng = np.random.default_rng(42)
rows = 1000

df = pd.DataFrame({
    "timestamp": pd.date_range(
        end=pd.Timestamp.now().floor("min"),
        periods=rows,
        freq="min",
    ),
    "src_ip": [
        f"192.168.1.{x}" for x in rng.integers(2, 250, rows)
    ],
    "dst_ip": [
        f"10.0.0.{x}" for x in rng.integers(2, 250, rows)
    ],
    "src_port": rng.integers(1024, 65535, rows),
    "dst_port": rng.choice([22, 53, 80, 443, 445, 3389, 8080], rows),
    "protocol": rng.choice(["TCP", "UDP", "ICMP"], rows),
    "packet_count": rng.integers(1, 200, rows),
    "bytes": rng.integers(64, 50000, rows),
    "connection_attempts": rng.integers(1, 5, rows),
    "label": "normal",
})

# Add controlled examples for testing the detector.
df.loc[10:20, "connection_attempts"] = 15
df.loc[30:40, "packet_count"] = 1500
df.loc[50:55, "bytes"] = 2_000_000
df.loc[60:65, "label"] = "attack"

Path("data").mkdir(exist_ok=True)
df.to_csv("data/network_traffic.csv", index=False)

print(f"Generated {len(df)} traffic records.")
print("File: data/network_traffic.csv")
