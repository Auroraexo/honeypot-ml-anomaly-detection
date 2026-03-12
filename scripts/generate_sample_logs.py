"""
生成合成 Cowrie 与 Zeek 日志，便于无真实流量时跑通检测流程。
用法: python scripts/generate_sample_logs.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"


def write_cowrie_samples() -> None:
    (DATA / "cowrie").mkdir(parents=True, exist_ok=True)
    out = DATA / "cowrie" / "cowrie.json"
    events = [
        {"eventid": "cowrie.session.connect", "timestamp": "2025-03-12T10:00:01Z", "src_ip": "192.168.1.100", "session": "s1", "duration": 0},
        {"eventid": "cowrie.login.failed", "timestamp": "2025-03-12T10:00:02Z", "src_ip": "192.168.1.100", "session": "s1", "username": "root", "password": "123"},
        {"eventid": "cowrie.login.failed", "timestamp": "2025-03-12T10:00:03Z", "src_ip": "192.168.1.100", "session": "s1", "username": "root", "password": "admin"},
        {"eventid": "cowrie.command.input", "timestamp": "2025-03-12T10:00:10Z", "src_ip": "192.168.1.100", "session": "s1", "input": "whoami"},
        {"eventid": "cowrie.session.closed", "timestamp": "2025-03-12T10:00:30Z", "src_ip": "192.168.1.100", "session": "s1", "duration": 29},
        {"eventid": "cowrie.session.connect", "timestamp": "2025-03-12T10:01:00Z", "src_ip": "10.0.0.50", "session": "s2", "duration": 0},
        {"eventid": "cowrie.login.success", "timestamp": "2025-03-12T10:01:01Z", "src_ip": "10.0.0.50", "session": "s2", "username": "root", "password": "root"},
        {"eventid": "cowrie.command.input", "timestamp": "2025-03-12T10:01:05Z", "src_ip": "10.0.0.50", "session": "s2", "input": "id"},
        {"eventid": "cowrie.session.closed", "timestamp": "2025-03-12T10:01:20Z", "src_ip": "10.0.0.50", "session": "s2", "duration": 19},
    ]
    with open(out, "w", encoding="utf-8") as f:
        for evt in events:
            f.write(json.dumps(evt, ensure_ascii=False) + "\n")
    print(f"Wrote {out}")


def write_zeek_samples() -> None:
    (DATA / "zeek").mkdir(parents=True, exist_ok=True)
    conn_path = DATA / "zeek" / "conn.log"
    conn_header = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\n"
    conn_rows = [
        "1731312001.000000\tC1\t192.168.1.100\t54321\t10.0.0.1\t22\ttcp\tssh\t25.0\t1000\t500\tSF\t10\t5\n",
        "1731312061.000000\tC2\t10.0.0.50\t44322\t10.0.0.1\t22\ttcp\tssh\t15.0\t800\t400\tSF\t8\t4\n",
    ]
    with open(conn_path, "w", encoding="utf-8") as f:
        f.write(conn_header)
        f.writelines(conn_rows)
    ssh_path = DATA / "zeek" / "ssh.log"
    ssh_header = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tauth_success\tdirection\n"
    ssh_rows = [
        "1731312001.000000\tC1\t192.168.1.100\t54321\t10.0.0.1\t22\tSSH-2.0-\tF\tinbound\n",
        "1731312061.000000\tC2\t10.0.0.50\t44322\t10.0.0.1\t22\tSSH-2.0-\tT\tinbound\n",
    ]
    with open(ssh_path, "w", encoding="utf-8") as f:
        f.write(ssh_header)
        f.writelines(ssh_rows)
    print(f"Wrote {conn_path}, {ssh_path}")


def main() -> None:
    write_cowrie_samples()
    write_zeek_samples()


if __name__ == "__main__":
    main()
