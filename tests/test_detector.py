import pandas as pd
from detector import detect_intrusions


def make_row(**overrides):
    row = {
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "src_port": 50000,
        "dst_port": 8080,
        "protocol": "TCP",
        "packet_count": 10,
        "bytes": 500,
        "connection_attempts": 1,
    }
    row.update(overrides)
    return row


def test_repeated_connection_attempts():
    result = detect_intrusions(pd.DataFrame([
        make_row(connection_attempts=20)
    ]))
    assert bool(result.loc[0, "alert"])
    assert result.loc[0, "alert_type"] == "Repeated Connection Attempts"


def test_normal_traffic():
    result = detect_intrusions(pd.DataFrame([make_row()]))
    assert not bool(result.loc[0, "alert"])


def test_high_packet_volume():
    result = detect_intrusions(pd.DataFrame([
        make_row(packet_count=1500)
    ]))
    assert bool(result.loc[0, "alert"])
    assert result.loc[0, "alert_type"] == "High Packet Volume"


def test_sensitive_port():
    result = detect_intrusions(pd.DataFrame([
        make_row(dst_port=445)
    ]))
    assert bool(result.loc[0, "alert"])
    assert result.loc[0, "alert_type"] == "Sensitive Port Connection"
