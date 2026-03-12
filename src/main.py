"""
入口：定时扫描 Cowrie/Zeek 日志 → 解析 → 特征提取 → 孤立森林检测 → 告警输出。
"""
import os
import sys
import time
import json
from pathlib import Path

import yaml

# 保证项目根在 path 中（Docker 中 WORKDIR 为 /app）
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.parser.cowrie_parser import CowrieParser
from src.parser.zeek_parser import ZeekParser
from src.features.feature_extractor import FeatureExtractor
from src.model.isolation_forest import IsolationForestDetector
from src.alert.alert_output import AlertOutput
from src.intel.threat_intel import ThreatIntel


def load_config() -> dict:
    config_path = ROOT / "config" / "config.yaml"
    if not config_path.exists():
        return {
            "paths": {
                "cowrie_log_dir": "data/cowrie",
                "zeek_log_dir": "data/zeek",
                "model_dir": "data/model",
                "alert_dir": "data/alerts",
            },
            "model": {"contamination": 0.01, "n_estimators": 100, "random_state": 42},
            "detector": {"poll_interval_seconds": 60, "train_min_samples": 2},
        }
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_once(cfg: dict, detector: IsolationForestDetector, extractor: FeatureExtractor, alert_out: AlertOutput) -> None:
    base = ROOT
    cowrie_dir = base / cfg["paths"]["cowrie_log_dir"]
    zeek_dir = base / cfg["paths"]["zeek_log_dir"]

    cowrie_parser = CowrieParser(str(cowrie_dir))
    zeek_parser = ZeekParser(str(zeek_dir))

    cowrie_rows = cowrie_parser.parse()
    zeek_conn, zeek_ssh = zeek_parser.parse()

    df = extractor.extract(cowrie_rows, zeek_conn, zeek_ssh)
    if df.empty:
        print(f"[cycle] cowrie={len(cowrie_rows)} zeek_conn={len(zeek_conn)} zeek_ssh={len(zeek_ssh)} -> no features")
        return
    X = extractor.get_feature_matrix(df)
    if len(X) == 0:
        print(f"[cycle] cowrie={len(cowrie_rows)} zeek_conn={len(zeek_conn)} zeek_ssh={len(zeek_ssh)} -> empty matrix")
        return

    train_min = cfg.get("detector", {}).get("train_min_samples", 50)
    model_path = base / cfg["paths"]["model_dir"] / "iforest.pkl"

    if detector.model is None:
        if len(X) >= train_min:
            detector.fit(X)
            detector.save(str(model_path))
            detector.load(str(model_path))
            print(f"[cycle] trained model on {len(X)} samples -> {model_path}")
        else:
            print(f"[cycle] waiting for training data: samples={len(X)}/{train_min}")
            return
    # 预测
    pred = detector.predict(X)
    scores = detector.score_samples(X)
    threat_intel_path = base / "config" / "threat_intel.yaml"
    ti = ThreatIntel(str(threat_intel_path))
    cooldown_seconds = int(cfg.get("detector", {}).get("alert_cooldown_seconds", 0))
    state_path = base / cfg["paths"]["alert_dir"] / ".alert_state.json"
    last_alert = {}
    if cooldown_seconds > 0 and state_path.exists():
        try:
            last_alert = json.loads(state_path.read_text(encoding="utf-8")) or {}
        except Exception:
            last_alert = {}

    anomalies = []
    for i, label in enumerate(pred):
        if label == -1:
            row = df.iloc[i]
            alert = {
                "src_ip": str(row.get("src_ip", "")),
                "score": float(scores[i]),
                "features": row.drop("src_ip").astype(str).to_dict() if "src_ip" in row else {},
            }
            anomalies.append(ti.enrich_alert(alert))
    # 演示模式：样本很少且无异常时，将得分最低的 1 条视为异常，便于答辩/截图
    demo_max_samples = int(cfg.get("detector", {}).get("demo_force_anomaly_below_samples", 0))
    if not anomalies and demo_max_samples > 0 and len(X) <= demo_max_samples and len(X) > 0:
        i = int(scores.argmin())
        row = df.iloc[i]
        alert = {
            "src_ip": str(row.get("src_ip", "")),
            "score": float(scores[i]),
            "features": row.drop("src_ip").astype(str).to_dict() if "src_ip" in row else {},
            "demo_forced": True,
        }
        anomalies.append(ti.enrich_alert(alert))
    if anomalies:
        # 告警冷却：同一 src_ip 在 cooldown 时间内只输出一次
        if cooldown_seconds > 0:
            now = time.time()
            filtered = []
            for a in anomalies:
                ip = str(a.get("src_ip", "")).strip()
                ts = float(last_alert.get(ip, 0) or 0)
                if not ip or now - ts >= cooldown_seconds:
                    filtered.append(a)
                    last_alert[ip] = now
            anomalies = filtered
            if anomalies:
                state_path.parent.mkdir(parents=True, exist_ok=True)
                state_path.write_text(json.dumps(last_alert, ensure_ascii=False, indent=2), encoding="utf-8")
        if anomalies:
            alert_out.write(anomalies, use_json=True)
        else:
            print(f"[cycle] predicted {len(X)} samples -> anomalies suppressed by cooldown")
    else:
        print(f"[cycle] predicted {len(X)} samples -> anomalies=0")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run one detection cycle then exit")
    args = parser.parse_args()

    cfg = load_config()
    paths = cfg["paths"]
    model_cfg = cfg.get("model", {})
    base = ROOT
    model_path = base / paths["model_dir"] / "iforest.pkl"

    detector = IsolationForestDetector(
        contamination=model_cfg.get("contamination", 0.01),
        n_estimators=model_cfg.get("n_estimators", 100),
        random_state=model_cfg.get("random_state", 42),
        model_path=str(model_path),
    )
    detector.load()
    extractor = FeatureExtractor()
    alert_out = AlertOutput(str(base / paths["alert_dir"]))

    if args.once:
        print("[startup] running once")
        run_once(cfg, detector, extractor, alert_out)
        return
    interval = cfg.get("detector", {}).get("poll_interval_seconds", 60)
    print(f"[startup] detector started, poll_interval_seconds={interval}. Press Ctrl+C to stop.")
    try:
        while True:
            run_once(cfg, detector, extractor, alert_out)
            time.sleep(interval)
    except KeyboardInterrupt:
        # 友好退出，不打印堆栈
        print("Detector stopped by user (Ctrl+C).")


if __name__ == "__main__":
    main()