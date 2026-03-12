"""
告警输出：将异常记录格式化为可读文本或 JSON，写入 data/alerts 并打印到控制台。
"""
import json
from datetime import datetime
from pathlib import Path


class AlertOutput:
    """接收异常记录，写入文件并打印。"""

    def __init__(self, alert_dir: str):
        self.alert_dir = Path(alert_dir)
        self.alert_dir.mkdir(parents=True, exist_ok=True)

    def write(self, records: list[dict], use_json: bool = True) -> None:
        """
        将异常记录写入告警目录并按日期命名；同时打印到控制台。
        records 每项建议包含 src_ip, score, features 等。
        """
        if not records:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = self.alert_dir / f"alerts_{ts}"
        if use_json:
            path = base.with_suffix(".json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(records, f, ensure_ascii=False, indent=2)
        else:
            path = base.with_suffix(".txt")
            lines = [self._format_one(r) for r in records]
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        for r in records:
            print("[ALERT]", self._format_one(r))
        print(f"Wrote {len(records)} alert(s) to {path}")

    def _format_one(self, r: dict) -> str:
        """单条告警可读格式。"""
        parts = [f"src_ip={r.get('src_ip', '')}", f"score={r.get('score', '')}"]
        if "features" in r:
            parts.append(f"features={r.get('features')}")
        return " | ".join(str(p) for p in parts)
