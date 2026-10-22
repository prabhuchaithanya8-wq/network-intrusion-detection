import pandas as pd


def detect_intrusions(df: pd.DataFrame) -> pd.DataFrame:
    """Apply transparent heuristic rules to network traffic records."""
    result = df.copy()
    result["alert"] = False
    result["alert_type"] = "Normal"
    result["severity"] = "Low"

    def flag(mask, name, severity):
        mask = mask.fillna(False) & ~result["alert"]
        result.loc[mask, "alert"] = True
        result.loc[mask, "alert_type"] = name
        result.loc[mask, "severity"] = severity

    flag(result["packet_count"] >= 1000, "High Packet Volume", "Medium")
    flag(
        result["dst_port"].isin([21, 23, 445, 1433, 3389]),
        "Sensitive Port Connection",
        "Medium",
    )
    flag(
        result["connection_attempts"] >= 10,
        "Repeated Connection Attempts",
        "High",
    )
    flag(result["bytes"] >= 1_000_000, "High Data Transfer", "Medium")

    if "label" in result.columns:
        known_attack = result["label"].astype(str).str.lower().isin(
            ["attack", "malicious", "intrusion"]
        )
        flag(known_attack, "Known Attack Label", "High")

    return result
