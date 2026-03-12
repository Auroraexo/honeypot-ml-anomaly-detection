"""
Cowrie SSH 蜜罐 JSON 日志解析器。
解析 session、login、command 等事件，提取时间戳、源 IP、用户名、密码、命令等。
"""
import json
import os
from pathlib import Path
from typing import Iterator


class CowrieParser:
    """解析 Cowrie 输出的 JSON 行日志。"""

    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)

    def _iter_json_lines(self) -> Iterator[dict]:
        """遍历日志目录下所有 .json 文件，逐行 yield JSON 对象。"""
        if not self.log_dir.exists():
            return
        for path in sorted(self.log_dir.rglob("*.json")):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
            except OSError:
                continue

    def parse(self) -> list[dict]:
        """
        解析所有 Cowrie 日志，返回统一格式的记录列表。
        每条记录包含: timestamp, src_ip, session, eventid, username, password, input, duration
        """
        rows = []
        for obj in self._iter_json_lines():
            record = self._normalize(obj)
            if record:
                rows.append(record)
        return rows

    def _normalize(self, obj: dict) -> dict | None:
        """将单条 Cowrie 事件转为统一字段。"""
        eventid = obj.get("eventid") or obj.get("event_id")
        if not eventid:
            return None
        ts = obj.get("timestamp")
        src_ip = obj.get("src_ip") or obj.get("peerIP") or ""
        session = obj.get("session") or obj.get("sessno") or ""
        username = obj.get("username") or ""
        password = obj.get("password") or ""
        # 命令输入
        cmd = obj.get("input") or obj.get("message") or ""
        if isinstance(cmd, dict):
            cmd = cmd.get("input", "") or ""
        duration = obj.get("duration") or 0
        if isinstance(duration, (int, float)):
            pass
        else:
            duration = 0
        return {
            "timestamp": ts,
            "src_ip": str(src_ip),
            "session": str(session),
            "eventid": str(eventid),
            "username": str(username),
            "password": str(password),
            "input": str(cmd)[:500],
            "duration": float(duration),
        }
