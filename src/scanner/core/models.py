"""
Models for secret scanning.
Use dataclasses and pydantic for validation.
******

Модели данных для сканера секретов.
Используют dataclasses и pydantic для валидации.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum
from pathlib import Path


class RiskLevel(Enum): # ensures that the risk can only be one of 4 values
    """
        Security risk level.
        ****
        Уровни риска для найденных уязвимостей.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PipelineContext:
    """
    The pipeline context for risk assessment.
    It is filled in by the parser based on the CI/CD file structure.
    *****
    Контекст пайплайна для оценки риска.
    Заполняется парсером на основе структуры CI/CD файла.
    """
    ci_system: str = ""
    stage: str = ""
    job_name: str = ""
    environment: str = ""
    image: str = ""
    is_production: bool = False # секрет в продакшене опаснее, чем в тесте
    section: str = ""  # variables, script, env, etc.
    variable_name: str = ""

    def to_dict(self) -> dict:
        """Конвертирует в словарь для JSON-сериализации."""
        return {
            "ci_system": self.ci_system,
            "stage": self.stage,
            "job_name": self.job_name,
            "environment": self.environment,
            "image": self.image,
            "is_production": self.is_production,
            "section": self.section,
            "variable_name": self.variable_name,
        }


@dataclass
class Finding:
    """
    The result of the check is a potential secret found.

    This is the main object that runs through the entire pipeline.:
    Detector →  Validator → Risk Coverage → Reporter

    *****

    Результат проверки — найденный потенциальный секрет.
    1 объект Finding - 1 найденный потенциальный секрет.

    Это основной объект, который проходит через весь пайплайн:
    Detector → Validator → RiskScorer → Reporter
    """
    file: str
    line: int
    secret_type: str
    value: str
    redacted_value: str
    is_hardcoded: bool # хардкод или переменная окружения
    context: PipelineContext = field(default_factory=PipelineContext)
    risk_score: float = 5.0 # 0-10
    risk_level: RiskLevel = RiskLevel.MEDIUM
    detected_at: datetime = field(default_factory=datetime.now)
    additional_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Конвертирует в словарь для JSON-сериализации."""
        return {
            "file": self.file,
            "line": self.line,
            "secret_type": self.secret_type,
            "value": self.redacted_value,
            "is_hardcoded": self.is_hardcoded,
            "context": self.context.to_dict(),
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level.value,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class ScanResult:
    """
    The result of scanning a file or directory.
    It contains all the findings and metadata of the scan.

    *****
    Результат сканирования файла или директории.
    Содержит все находки и метаданные сканирования.
    """
    findings: list[Finding]
    files_scanned: int
    scan_duration_ms: float
    ci_systems_detected: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Конвертирует в словарь для JSON-сериализации."""
        return {
            "findings": [f.to_dict() for f in self.findings],       # Все файндинги
            "files_scanned": self.files_scanned,                    # Cколько файлов проверили
            "scan_duration_ms": round(self.scan_duration_ms, 2),    # Время выполнения
            "ci_systems_detected": self.ci_systems_detected,        # Конфиги каких cicd систем обнаружены
            "errors": self.errors,                                  # Ошибки при сканировании
            "summary": {
                "total": len(self.findings),
                "hardcoded": sum(1 for f in self.findings if f.is_hardcoded),
                "critical": sum(1 for f in self.findings if f.risk_level == RiskLevel.CRITICAL),
                "high": sum(1 for f in self.findings if f.risk_level == RiskLevel.HIGH),
                "medium": sum(1 for f in self.findings if f.risk_level == RiskLevel.MEDIUM),
                "low": sum(1 for f in self.findings if f.risk_level == RiskLevel.LOW),
            }
        }

    @property
    def has_critical(self) -> bool:
        """Проверяет наличие критических уязвимостей."""
        return any(f.risk_level == RiskLevel.CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        """Проверяет наличие высокоуровневых уязвимостей."""
        return any(f.risk_level == RiskLevel.HIGH for f in self.findings)