"""
简易威胁情报模块：读取高风险 IP 列表，并用于告警增强/标注。

毕业设计可落地版本（不依赖外部付费 API）：通过本地 YAML 维护即可。
"""

from __future__ import annotations

from pathlib import Path
from typing import Set

import yaml


class ThreatIntel:
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.high_risk_ips: Set[str] = set()
        self.tag_on_match: bool = True
        self.reload()

    def reload(self) -> None:
        if not self.config_path.exists():
            self.high_risk_ips = set()
            self.tag_on_match = True
            return
        with open(self.config_path, "r", encoding="utf-8") as f:
            obj = yaml.safe_load(f) or {}
        ti = obj.get("threat_intel") or {}
        ips = ti.get("high_risk_ips") or []
        self.high_risk_ips = {str(x).strip() for x in ips if str(x).strip()}
        self.tag_on_match = bool(ti.get("tag_on_match", True))

    def is_high_risk(self, ip: str) -> bool:
        return str(ip).strip() in self.high_risk_ips

    def enrich_alert(self, alert: dict) -> dict:
        ip = str(alert.get("src_ip", "")).strip()
        if self.tag_on_match and ip and self.is_high_risk(ip):
            tags = set(alert.get("tags") or [])
            tags.add("threat_intel:high_risk_ip")
            alert["tags"] = sorted(tags)
            alert["threat_intel_hit"] = True
        else:
            alert["threat_intel_hit"] = False
        return alert

