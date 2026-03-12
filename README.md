# 内网异常流量检测系统

基于高交互蜜罐（Cowrie）与 Zeek 流量采集、Python 日志解析与特征提取、孤立森林异常检测、Docker 一键部署的内网异常流量检测系统。

## 功能

1. **流量采集**：Cowrie SSH 蜜罐 + Zeek 网络分析
2. **日志解析与特征提取**：解析 Cowrie JSON 与 Zeek conn/ssh 日志，按源 IP 聚合特征
3. **异常检测**：孤立森林算法训练与预测
4. **攻击告警**：异常结果输出到 `data/alerts/` 并打印到控制台（支持威胁情报标签增强）
5. **一键启动**：`docker-compose up -d` 启动全部服务
6. **动态自适应演示（增强项）**：提供 Cowrie profile 轮换脚本（端口暴露/服务开关），以及可选 K8s 扩缩容示例

## 目录结构

```
├── docker-compose.yml    # Cowrie、Zeek、检测器
├── Dockerfile            # 检测器镜像
├── requirements.txt
├── config/config.yaml    # 路径与模型参数
├── config/cowrie_profiles.yaml  # Cowrie 动态 profile（增强项）
├── config/threat_intel.yaml     # 简易威胁情报（增强项）
├── src/
│   ├── main.py           # 入口
│   ├── parser/           # Cowrie、Zeek 解析
│   ├── features/         # 特征提取
│   ├── model/            # 孤立森林
│   └── alert/            # 告警输出
├── data/
│   ├── cowrie/           # Cowrie 日志（挂载）
│   ├── zeek/             # Zeek 日志（挂载）
│   ├── model/            # 持久化模型
│   └── alerts/           # 告警文件
└── scripts/
    └── generate_sample_logs.py  # 合成日志，便于本地跑通
```

## 快速开始

### 方式一：Docker 一键启动

```bash
docker-compose up -d
```

- **Cowrie**：SSH 蜜罐，端口 `2222`，可用 `ssh -p 2222 root@localhost` 测试
- **Zeek**：流量分析，日志写入 `data/zeek/`
- **detector**：定时读取 `data/cowrie`、`data/zeek`，训练/预测并写告警到 `data/alerts/`

查看检测器日志：

```bash
docker-compose logs -f detector
```

告警文件位置：`data/alerts/`（JSON 与控制台输出）。

### 动态自适应演示（增强项）

本项目提供“可演示的动态策略切换”，用于对应开题报告中“动态自适应”的描述（不依赖 eBPF 内核改动）。
在 profile 切换时，会同时轮换 Cowrie 的 `honeyfs` 标识文件（例如 `issue.net`/`motd`），从而让 SSH 登录前/后提示信息呈现为不同“系统外观”，用于“动态指纹/伪装”演示。

1. 查看可用 profile：

```bash
python scripts/rotate_cowrie_profile.py --list
```

2. 应用某个 profile（会生成 `docker-compose.override.yml` 并重建 cowrie 服务）：

```bash
python scripts/rotate_cowrie_profile.py --apply ssh_telnet
```

验证“动态指纹”是否生效（任选其一）：

- 直接 SSH 连接观察 banner（以 2222 为例）：

```bash
ssh -p 2222 root@localhost
```

- 或者仅抓取首屏文本（不登录）：

```bash
ssh -p 2222 root@localhost
```

3. 轮换一次 / 持续轮换：

```bash
python scripts/rotate_cowrie_profile.py --rotate-once
python scripts/rotate_cowrie_profile.py --rotate-forever
```

### 方式二：本地运行（无 Docker）

1. 安装 Python 3.10+，安装依赖：

   ```bash
   pip install -r requirements.txt
   ```

2. 生成合成日志（无真实流量时也可跑通流程）：

   ```bash
   python scripts/generate_sample_logs.py
   ```

3. 启动检测器（需在项目根目录）：

   ```bash
   python src/main.py
   ```

   检测器会按 `config/config.yaml` 中的 `poll_interval_seconds` 定时扫描日志、训练或预测，并将异常写入 `data/alerts/`。可用 `python src/main.py --once` 只运行一轮后退出，便于测试。

## 配置说明

`config/config.yaml`：

- **paths**：`cowrie_log_dir`、`zeek_log_dir`、`model_dir`、`alert_dir`
- **model**：`contamination`、`n_estimators`、`random_state`（孤立森林参数）
- **detector**：`poll_interval_seconds`（轮询间隔）、`train_min_samples`（最少样本数再训练）

`config/threat_intel.yaml`：

- **high_risk_ips**：高风险 IP 列表（命中时告警会增加 `tags: ["threat_intel:high_risk_ip"]`）

## 说明

- 首次运行需积累一定样本（见配置 `train_min_samples`，默认 2）才会训练模型并开始预测；可先运行 `scripts/generate_sample_logs.py` 生成合成数据。
- Cowrie 容器日志目录若与宿主路径不一致，可调整 `docker-compose.yml` 中 cowrie 的 `volumes` 挂载。
- Zeek 容器默认以空输入运行；若有 pcap 或需监听网卡，可修改 zeek 的 `command` 并挂载相应资源。
- Kubernetes 可选部署示例见 `k8s/README.md`（用于扩缩容展示）。

## 技术栈

- Python 3.10、scikit-learn、pandas、PyYAML
- Cowrie、Zeek、Docker / docker-compose
