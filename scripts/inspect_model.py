"""
读取 data/model/iforest.pkl（pickle 模型）并导出为可读 JSON。

用法（在项目根目录）:
  py -3 scripts/inspect_model.py
"""

import json
import pickle
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    import sys
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from src.features.feature_extractor import FeatureExtractor

    model_path = root / "data" / "model" / "iforest.pkl"
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    with open(model_path, "rb") as f:
        model = pickle.load(f)

    feature_names = FeatureExtractor().feature_names_
    feature_desc = {
        "conn_count": "连接/事件数量（按源 IP 聚合后的计数）",
        "total_orig_bytes": "源端发送字节总量（Zeek conn.log: orig_bytes）",
        "total_resp_bytes": "目的端返回字节总量（Zeek conn.log: resp_bytes）",
        "total_packets": "源端与目的端包数总和（orig_pkts + resp_pkts）",
        "total_duration": "连接/会话持续时间累加（Zeek duration + Cowrie duration）",
        "distinct_dst_ports": "访问的不同目标端口数（按源 IP 聚合）",
        "login_fail_count": "登录失败次数（Cowrie cowrie.login.failed）",
        "login_success_count": "登录成功次数（Cowrie cowrie.login.success）",
        "unique_commands": "唯一命令数量（Cowrie 命令输入去重计数）",
        "session_count": "会话数（Cowrie session 去重计数）",
    }

    info = {
        "model_path": str(model_path),
        "type": f"{type(model).__module__}.{type(model).__name__}",
        "feature_names": feature_names,
        "feature_descriptions": {k: feature_desc.get(k, "") for k in feature_names},
        "paper_note": (
            "本文件由 scripts/inspect_model.py 自动导出，用于论文/答辩展示模型关键参数与特征维度。"
            "IsolationForest 对应特征顺序与 feature_names 一致。"
        ),
        "paper_description": (
            "本系统以 Cowrie 高交互 SSH 蜜罐与 Zeek 网络分析日志为数据源，"
            "对内网主机/攻击源的行为进行特征化建模。首先解析 Cowrie 的会话、登录与命令交互事件，"
            "以及 Zeek 的连接（conn.log）与 SSH（ssh.log）记录；随后以源 IP 为聚合粒度构造连接数、"
            "字节数、包数、持续时间、目标端口多样性、登录失败/成功次数、命令多样性等特征向量。"
            "在无监督场景下采用 IsolationForest（孤立森林）学习“正常行为”的分布，"
            "对偏离正常模式的样本给出异常标签（-1）与异常分数（score）。"
            "当检测到异常时，系统将告警以 JSON 形式输出到 data/alerts 目录，并在控制台实时打印，"
            "便于实验复现与答辩演示。"
        ),
        "n_estimators": getattr(model, "n_estimators", None),
        "contamination": getattr(model, "contamination", None),
        "random_state": getattr(model, "random_state", None),
        "max_samples": getattr(model, "max_samples", None),
        "max_features": getattr(model, "max_features", None),
        "n_features_in_": getattr(model, "n_features_in_", None),
        "offset_": getattr(model, "offset_", None),
    }

    out_path = root / "data" / "model" / "model_info.json"
    out_path.write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {out_path}")

    md_lines = [
        "# 模型说明（IsolationForest）",
        "",
        info["paper_description"],
        "",
        "## 模型参数",
        f"- type: `{info['type']}`",
        f"- n_estimators: `{info['n_estimators']}`",
        f"- contamination: `{info['contamination']}`",
        f"- random_state: `{info['random_state']}`",
        f"- n_features_in_: `{info['n_features_in_']}`",
        "",
        "## 特征说明（顺序即训练/预测顺序）",
    ]
    for i, name in enumerate(feature_names, start=1):
        md_lines.append(f"{i}. **{name}**：{feature_desc.get(name, '')}")

    md_path = root / "data" / "model" / "model_info.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()

