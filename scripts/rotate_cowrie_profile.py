"""
动态轮换 Cowrie 配置（通过生成 docker-compose.override.yml 并重建 cowrie 服务）。

目标：让开题报告里“动态策略/伪装”的部分在毕业设计里可落地、可演示。
做法：在不改内核/eBPF 的前提下，利用 Cowrie Docker 的环境变量配置能力，
在不同 profile 间切换（例如开启/关闭 telnet、切换端口暴露）。

用法（项目根目录）:
  py -3 scripts/rotate_cowrie_profile.py --list
  py -3 scripts/rotate_cowrie_profile.py --apply default_ssh
  py -3 scripts/rotate_cowrie_profile.py --rotate-once
  py -3 scripts/rotate_cowrie_profile.py --rotate-forever

说明：
- 需要本机已安装 docker，并可使用 `docker compose` 命令。
- 生成的 override 文件路径：docker-compose.override.yml（与 docker-compose.yml 同级）
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
PROFILES_PATH = ROOT / "config" / "cowrie_profiles.yaml"
OVERRIDE_PATH = ROOT / "docker-compose.override.yml"


def load_profiles() -> dict:
    with open(PROFILES_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def render_override(profile: dict) -> str:
    override = {
        "services": {
            "cowrie": {
                "ports": profile.get("ports", []),
                "environment": profile.get("environment", {}) or {},
                "volumes": profile.get("volumes", []) or [],
            }
        }
    }
    return yaml.safe_dump(override, sort_keys=False, allow_unicode=True)


def docker_compose_up_cowrie() -> None:
    cmd = ["docker", "compose", "up", "-d", "--force-recreate", "cowrie"]
    subprocess.check_call(cmd, cwd=str(ROOT))


def apply_profile(name: str, profiles: dict) -> None:
    prof = profiles["profiles"].get(name)
    if not prof:
        raise KeyError(f"Profile not found: {name}")
    OVERRIDE_PATH.write_text(render_override(prof), encoding="utf-8")
    print(f"Wrote {OVERRIDE_PATH}")
    docker_compose_up_cowrie()
    print(f"Applied profile: {name}")


def rotate_once(profiles: dict) -> str:
    rot = profiles.get("rotation", {}) or {}
    order = rot.get("order", []) or []
    if not order:
        raise ValueError("rotation.order is empty in config/cowrie_profiles.yaml")

    current = None
    if OVERRIDE_PATH.exists():
        try:
            cur_obj = yaml.safe_load(OVERRIDE_PATH.read_text(encoding="utf-8")) or {}
            env = ((cur_obj.get("services") or {}).get("cowrie") or {}).get("environment") or {}
            ports = ((cur_obj.get("services") or {}).get("cowrie") or {}).get("ports") or []
            volumes = ((cur_obj.get("services") or {}).get("cowrie") or {}).get("volumes") or []
            # 通过 ports/env 粗略匹配当前 profile（足够用于演示）
            for name, prof in profiles["profiles"].items():
                if (
                    prof.get("ports", []) == ports
                    and (prof.get("environment") or {}) == env
                    and (prof.get("volumes") or []) == volumes
                ):
                    current = name
                    break
        except Exception:
            current = None

    if current in order:
        nxt = order[(order.index(current) + 1) % len(order)]
    else:
        nxt = order[0]
    apply_profile(nxt, profiles)
    return nxt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true", help="List available profiles")
    parser.add_argument("--apply", type=str, help="Apply a profile by name")
    parser.add_argument("--rotate-once", action="store_true", help="Rotate to next profile once")
    parser.add_argument("--rotate-forever", action="store_true", help="Rotate forever based on interval_seconds")
    args = parser.parse_args()

    if not PROFILES_PATH.exists():
        print(f"Missing {PROFILES_PATH}", file=sys.stderr)
        sys.exit(1)

    profiles = load_profiles()

    if args.list:
        for name, prof in (profiles.get("profiles") or {}).items():
            desc = prof.get("description", "")
            print(f"- {name}: {desc}")
        return

    if args.apply:
        apply_profile(args.apply, profiles)
        return

    if args.rotate_once:
        rotate_once(profiles)
        return

    if args.rotate_forever:
        interval = int((profiles.get("rotation") or {}).get("interval_seconds", 300))
        print(f"Rotate forever, interval_seconds={interval}. Press Ctrl+C to stop.")
        try:
            while True:
                rotate_once(profiles)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("Stopped.")
        return

    parser.print_help()


if __name__ == "__main__":
    main()

