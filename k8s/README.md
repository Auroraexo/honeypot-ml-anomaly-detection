# Kubernetes 可选部署（增强项）

本目录提供一个“可选增强”的 K8s 示例，用于在开题/论文中体现“可扩展部署能力”。  
注意：本项目的主线仍是 `docker-compose.yml` 一键启动；K8s 部分用于加分展示。

## 前置条件

- 已安装 Kubernetes（建议 `kind` / `minikube`）
- 本地可构建 detector 镜像（Dockerfile 已提供）

## 快速部署（示例）

1. 构建 detector 镜像（本地）：

```bash
docker build -t abnormal-traffic-detector:local .
```

2. 将镜像加载到 kind（如果你使用 kind）：

```bash
kind load docker-image abnormal-traffic-detector:local
```

3. 部署 Cowrie（2 副本）与 detector：

```bash
kubectl apply -f k8s/cowrie-deployment.yaml
kubectl apply -f k8s/cowrie-service.yaml
kubectl apply -f k8s/detector-deployment.yaml
```

4. 扩缩容蜜罐（演示“动态编排能力”）：

```bash
kubectl scale deployment/cowrie --replicas=5
```

## 说明

- `cowrie-service.yaml` 使用 NodePort `32222` 暴露 SSH（容器内 2222）。
- 日志卷当前使用 `emptyDir` 便于演示；如需持久化可替换为 PVC/hostPath。

