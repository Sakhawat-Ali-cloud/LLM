import re
import yaml
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Tuple


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class InjectionResult:
    score: float          # normalized 0–1
    risk_level: RiskLevel
    matched_patterns: List[Tuple[str, float]]


class InjectionDetector:

    def __init__(self, config_path="config.yaml"):
        self.config = self._load_config(config_path)
        self.keywords = self.config["injection_detection"]["keywords"]

        # FIXED: consistent thresholds (0–1 scale)
        self.thresholds = {
            "medium": 0.3,
            "high": 0.6,
            "block": 0.75
        }

        self._compile_patterns()

    def _load_config(self, path):
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f)
        except:
            return {
                "injection_detection": {
                    "keywords": {
                        "ignore previous instructions": 5,
                        "system prompt": 5,
                        "DAN": 4,
                        "developer mode": 4,
                        "bypass": 3,
                        "override": 3,
                        "reveal": 2,
                        "api key": 3,
                        "secret": 2,
                    }
                }
            }

    def _compile_patterns(self):
        self.patterns = {}
        max_w = max(self.keywords.values())

        for k, w in self.keywords.items():
            pattern = re.compile(re.escape(k), re.IGNORECASE)
            self.patterns[k] = (pattern, w / max_w)  # normalize weight

    def analyze(self, text: str) -> InjectionResult:
        if not text:
            return InjectionResult(0.0, RiskLevel.LOW, [])

        total = 0.0
        matches = []

        for k, (pattern, weight) in self.patterns.items():
            found = len(pattern.findall(text))
            if found:
                score = min(1.0, weight * found)
                total += score
                matches.append((k, score))

        # clamp final score
        total = min(1.0, total)

        # risk
        if total >= self.thresholds["high"]:
            risk = RiskLevel.HIGH
        elif total >= self.thresholds["medium"]:
            risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.LOW

        return InjectionResult(total, risk, matches)

    def should_block(self, result: InjectionResult) -> bool:
        return result.score >= self.thresholds["block"]