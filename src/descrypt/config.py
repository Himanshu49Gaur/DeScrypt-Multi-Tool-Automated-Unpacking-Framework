"""Configuration management for DeScrypt.

Paper References:
- Section 3.1: Configurable max_depth, timeout budget, modes
- Section 3.7: Tuned scoring weights
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import yaml


@dataclass
class EngineConfig:
    mode: str = "static"
    max_depth: int = 12
    time_budget_s: float = 300.0
    min_tool_confidence: float = 0.30


@dataclass
class ScoringConfig:
    malicious_threshold: float = 0.50
    js_eval_packer_weight: float = 0.10
    base64_min_length: int = 32


@dataclass
class DetectionConfig:
    entropy_clean_threshold: float = 6.5


@dataclass
class DeScryptConfig:
    engine: EngineConfig = field(default_factory=EngineConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)

    @classmethod
    def load(cls, config_path: Optional[Path | str] = None) -> DeScryptConfig:
        if config_path is None:
            default_path = Path("configs/default.yaml")
            if default_path.exists():
                config_path = default_path
            else:
                return cls()

        path = Path(config_path)
        if not path.exists():
            return cls()

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            engine_data = data.get("engine", {})
            scoring_data = data.get("scoring", {})
            detect_data = data.get("detection", {})

            return cls(
                engine=EngineConfig(**engine_data),
                scoring=ScoringConfig(**scoring_data),
                detection=DetectionConfig(**detect_data),
            )
        except Exception:
            return cls()
