"""
孤立森林异常检测：训练、预测与模型持久化。
"""
import pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest


class IsolationForestDetector:
    """封装 sklearn IsolationForest，支持训练、保存、加载与预测。"""

    def __init__(
        self,
        contamination: float = 0.01,
        n_estimators: int = 100,
        random_state: int = 42,
        model_path: str | None = None,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model_path = model_path
        self.model: IsolationForest | None = None

    def fit(self, X: np.ndarray) -> "IsolationForestDetector":
        """使用特征矩阵 X 训练孤立森林。"""
        if X is None or len(X) == 0:
            return self
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
        )
        self.model.fit(X)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """返回预测标签：-1 异常，1 正常。"""
        if self.model is None or X is None or len(X) == 0:
            return np.array([])
        return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """返回异常分数（越负越异常）。"""
        if self.model is None or X is None or len(X) == 0:
            return np.array([])
        return self.model.score_samples(X)

    def save(self, path: str | None = None) -> None:
        """持久化模型到 path 或 self.model_path。"""
        path = path or self.model_path
        if not path or self.model is None:
            return
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as f:
            pickle.dump(self.model, f)

    def load(self, path: str | None = None) -> "IsolationForestDetector":
        """从 path 或 self.model_path 加载模型。"""
        path = path or self.model_path
        if not path:
            return self
        p = Path(path)
        if not p.exists():
            return self
        with open(p, "rb") as f:
            self.model = pickle.load(f)
        return self
