"""
Zeek 网络分析日志解析器。
解析 conn.log、ssh.log 等 TSV 日志，按连接/会话提取字段。
"""
import gzip
from pathlib import Path
from typing import Iterator


class ZeekParser:
    """解析 Zeek 的 conn.log 与 ssh.log（支持 .log 与 .log.gz）。"""

    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)

    def _iter_tsv_rows(self, filename: str) -> Iterator[dict]:
        """读取 Zeek 日志文件（TSV，#fields 为列名），yield 每行为 dict。"""
        for name in (filename, filename + ".gz"):
            path = self.log_dir / name
            if not path.exists():
                continue
            open_fn = gzip.open if name.endswith(".gz") else open
            mode = "rt"
            kwargs = {"encoding": "utf-8", "errors": "ignore"}
            try:
                with open_fn(path, mode, **kwargs) as f:
                    fields = None
                    for line in f:
                        line = line.strip()
                        if line.startswith("#fields"):
                            fields = line.split("\t")[1:]
                            continue
                        if line.startswith("#") or not line or not fields:
                            continue
                        values = line.split("\t")
                        if len(values) >= len(fields):
                            yield dict(zip(fields, values[: len(fields)]))
            except OSError:
                continue
            break

    def parse_conn(self) -> list[dict]:
        """解析 conn.log，返回连接记录。"""
        rows = []
        for row in self._iter_tsv_rows("conn.log"):
            records = self._normalize_conn(row)
            if records:
                rows.append(records)
        return rows

    def _normalize_conn(self, row: dict) -> dict | None:
        """标准化 conn 行：ts, id.orig_h, id.resp_p, duration, orig_bytes, resp_bytes 等。"""
        try:
            ts = row.get("ts", "")
            orig_h = row.get("id.orig_h", "")
            orig_p = row.get("id.orig_p", "")
            resp_h = row.get("id.resp_h", "")
            resp_p = row.get("id.resp_p", "")
            duration = self._safe_float(row.get("duration", 0))
            orig_bytes = self._safe_float(row.get("orig_bytes", 0))
            resp_bytes = self._safe_float(row.get("resp_bytes", 0))
            orig_pkts = self._safe_float(row.get("orig_pkts", 0))
            resp_pkts = self._safe_float(row.get("resp_pkts", 0))
        except (TypeError, ValueError):
            return None
        return {
            "ts": ts,
            "src_ip": str(orig_h),
            "src_port": str(orig_p),
            "dst_ip": str(resp_h),
            "dst_port": str(resp_p),
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
        }

    def parse_ssh(self) -> list[dict]:
        """解析 ssh.log。"""
        rows = []
        for row in self._iter_tsv_rows("ssh.log"):
            norm = self._normalize_ssh(row)
            if norm:
                rows.append(norm)
        return rows

    def _normalize_ssh(self, row: dict) -> dict | None:
        """标准化 ssh 行。"""
        try:
            return {
                "ts": row.get("ts", ""),
                "src_ip": row.get("id.orig_h", ""),
                "dst_ip": row.get("id.resp_h", ""),
                "auth_success": str(row.get("auth_success", "")).lower() == "t",
            }
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _safe_float(v) -> float:
        if v == "-" or v is None or v == "":
            return 0.0
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    def parse(self) -> tuple[list[dict], list[dict]]:
        """解析 Zeek 目录下 conn 与 ssh，返回 (conn_list, ssh_list)。"""
        return self.parse_conn(), self.parse_ssh()
