"""
统一特征提取：按源 IP 或时间窗口聚合 Cowrie/Zeek 解析结果，输出数值特征向量供孤立森林使用。
"""
import numpy as np
import pandas as pd
from collections import defaultdict


class FeatureExtractor:
    """从 Cowrie 与 Zeek 解析结果中按源 IP 聚合并提取数值特征。"""

    def __init__(self):
        self.feature_names_ = [
            "conn_count",
            "total_orig_bytes",
            "total_resp_bytes",
            "total_packets",
            "total_duration",
            "distinct_dst_ports",
            "login_fail_count",
            "login_success_count",
            "unique_commands",
            "session_count",
        ]

    def extract(
        self,
        cowrie_rows: list[dict],
        zeek_conn_rows: list[dict],
        zeek_ssh_rows: list[dict] | None = None,
    ) -> pd.DataFrame:
        """
        聚合 Cowrie + Zeek 数据按 src_ip，生成一条记录 per IP，列即 feature_names_。
        """
        zeek_ssh_rows = zeek_ssh_rows or []
        by_ip: dict[str, dict] = defaultdict(lambda: defaultdict(lambda: 0))

        for r in cowrie_rows:
            ip = (r.get("src_ip") or "").strip() or "unknown"
            by_ip[ip]["conn_count"] += 1
            eventid = (r.get("eventid") or "").lower()
            if "login.failed" in eventid:
                by_ip[ip]["login_fail_count"] += 1
            elif "login.success" in eventid:
                by_ip[ip]["login_success_count"] += 1
            if r.get("input"):
                by_ip[ip].setdefault("_commands", set()).add((r.get("input") or "").strip()[:64])
            by_ip[ip]["total_duration"] += float(r.get("duration") or 0)
            if r.get("session"):
                by_ip[ip].setdefault("_sessions", set()).add(r["session"])

        for r in zeek_conn_rows:
            ip = (r.get("src_ip") or "").strip() or "unknown"
            by_ip[ip]["conn_count"] += 1
            by_ip[ip]["total_orig_bytes"] += float(r.get("orig_bytes") or 0)
            by_ip[ip]["total_resp_bytes"] += float(r.get("resp_bytes") or 0)
            by_ip[ip]["total_packets"] += float(r.get("orig_pkts") or 0) + float(r.get("resp_pkts") or 0)
            by_ip[ip]["total_duration"] += float(r.get("duration") or 0)
            by_ip[ip].setdefault("_ports", set()).add((r.get("dst_port") or "").strip())

        for r in zeek_ssh_rows:
            ip = (r.get("src_ip") or "").strip() or "unknown"
            by_ip[ip]["conn_count"] += 1

        rows = []
        for ip, agg in by_ip.items():
            commands = agg.get("_commands") or set()
            sessions = agg.get("_sessions") or set()
            ports = agg.get("_ports") or set()
            rows.append({
                "src_ip": ip,
                "conn_count": agg["conn_count"],
                "total_orig_bytes": agg["total_orig_bytes"],
                "total_resp_bytes": agg["total_resp_bytes"],
                "total_packets": agg["total_packets"],
                "total_duration": agg["total_duration"],
                "distinct_dst_ports": len(ports),
                "login_fail_count": agg["login_fail_count"],
                "login_success_count": agg["login_success_count"],
                "unique_commands": len(commands),
                "session_count": len(sessions),
            })
        if not rows:
            return pd.DataFrame(columns=["src_ip"] + self.feature_names_)
        df = pd.DataFrame(rows)
        df = df.fillna(0)
        return df

    def get_feature_matrix(self, df: pd.DataFrame) -> np.ndarray:
        """从 extract 得到的 DataFrame 中取数值特征矩阵（无 src_ip）。"""
        if df.empty:
            return np.zeros((0, len(self.feature_names_)))
        cols = [c for c in self.feature_names_ if c in df.columns]
        if len(cols) != len(self.feature_names_):
            for n in self.feature_names_:
                if n not in df.columns:
                    df[n] = 0
            cols = self.feature_names_
        return df[cols].astype(float).values
