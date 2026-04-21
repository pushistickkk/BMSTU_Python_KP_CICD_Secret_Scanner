"""
Модели данных для сканера секретов.

Этот модуль предоставляет dataclasses для представления:
- PipelineContext: Контекст CI/CD пайплайна
- Finding: Найденная уязвимость
- ScanResult: Результат сканирования
- RiskLevel: Уровни риска (enum)

Пример использования:
    >>> from scanner.core.models import Finding, PipelineContext, RiskLevel
    >>> ctx = PipelineContext(ci_system="gitlab", stage="deploy", is_production=True)
    >>> finding = Finding(
    ...     file=".gitlab-ci.yml",
    ...     line=10,
    ...     secret_type="AWS_ACCESS_KEY_ID",
    ...     value="AKIAIOSFODNN7EXAMPLE",
    ...     redacted_value="AKIA***MPLE",
    ...     is_hardcoded=True,
    ...     context=ctx
    ... )
    >>> print(finding.secret_type, finding.risk_level)
    AWS_ACCESS_KEY_ID RiskLevel.MEDIUM
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum
from pathlib import Path


class RiskLevel(Enum):
    """
    Уровни риска для найденных уязвимостей.

    Используется для классификации секретов по степени критичности.
    Значения соответствуют порогам в ContextAwareRiskScorer.get_level().

    Values:
        LOW (str): Низкий риск (score < 4.0) — можно игнорировать
        MEDIUM (str): Средний риск (4.0 <= score < 6.5) — требует внимания
        HIGH (str): Высокий риск (6.5 <= score < 8.5) — исправить в приоритете
        CRITICAL (str): Критический риск (score >= 8.5) — исправить немедленно

    Example:
        >>> RiskLevel.CRITICAL.value
        'critical'
        >>> RiskLevel('high')
        <RiskLevel.HIGH: 'high'>
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PipelineContext:
    """
    Контекст пайплайна для оценки риска.

    Заполняется парсером на основе структуры CI/CD файла.
    Используется для многофакторного риск-скоринга.

    Attributes:
        ci_system (str): Тип CI/CD системы ('gitlab', 'github', 'jenkins')
        stage (str): Этап пайплайна ('build', 'test', 'deploy', 'lint')
        job_name (str): Имя джобы в пайплайне
        environment (str): Окружение ('production', 'staging', 'development')
        image (str): Docker image (если используется в джобе)
        is_production (bool): Флаг production окружения — повышает риск
        section (str): Секция конфига ('variables', 'script', 'env', 'with')
        variable_name (str): Имя переменной (если значение из variables/env)

    Example:
        >>> ctx = PipelineContext(
        ...     ci_system="gitlab",
        ...     stage="deploy",
        ...     environment="production",
        ...     is_production=True,
        ...     job_name="deploy_prod"
        ... )
        >>> print(ctx.ci_system, ctx.is_production)
        gitlab True
        >>> ctx_dict = ctx.to_dict()
        >>> print(ctx_dict['stage'])
        deploy
    """
    ci_system: str = ""
    stage: str = ""
    job_name: str = ""
    environment: str = ""
    image: str = ""
    is_production: bool = False  # секрет в продакшене опаснее, чем в тесте
    section: str = ""  # variables, script, env, etc.
    variable_name: str = ""

    def to_dict(self) -> dict:
        """
        Конвертирует контекст в словарь для JSON-сериализации.

        Используется при экспорте результатов в JSON/SARIF форматы.

        Returns:
            dict: Словарь с полями контекста.
                 Все значения — примитивные типы (str, bool).

        Example:
            >>> ctx = PipelineContext(ci_system="github", stage="test")
            >>> d = ctx.to_dict()
            >>> print(d['ci_system'])
            github
        """
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
    Результат проверки — найденный потенциальный секрет.

    Это основной объект, который проходит через весь пайплайн сканера:
    1. Detector: Создаёт Finding при обнаружении паттерна
    2. Validator: Может скорректировать risk_score
    3. RiskScorer: Вычисляет итоговый риск на основе контекста
    4. Reporter: Форматирует для вывода

    Один объект Finding = одна найденная потенциальная уязвимость.

    Attributes:
        file (str): Путь к файлу с уязвимостью
        line (int): Номер строки с уязвимостью (1-based)
        secret_type (str): Тип обнаруженного секрета (например, 'AWS_ACCESS_KEY_ID')
        value (str): Оригинальное значение секрета (не маскированное)
        redacted_value (str): Замаскированное значение для безопасного вывода
        is_hardcoded (bool): True если хардкод, False если переменная окружения
        context (PipelineContext): Контекст пайплайна для риск-скоринга
        risk_score (float): Числовая оценка риска в диапазоне [0.0, 10.0]
        risk_level (RiskLevel): Категориальный уровень риска (LOW/MEDIUM/HIGH/CRITICAL)
        detected_at (datetime): Время обнаружения уязвимости
        additional_data (dict): Дополнительные данные от детекторов/валидаторов
        detector_name (str): Название детектора нашедшего этот секрет

    Example:
        >>> from scanner.core.models import Finding, PipelineContext
        >>> ctx = PipelineContext(ci_system="gitlab", stage="deploy", is_production=True)
        >>> finding = Finding(
        ...     file=".gitlab-ci.yml",
        ...     line=10,
        ...     secret_type="AWS_ACCESS_KEY_ID",
        ...     value="AKIAIOSFODNN7EXAMPLE",
        ...     redacted_value="AKIA***MPLE",
        ...     is_hardcoded=True,
        ...     context=ctx,
        ...     detector_name="RegexDetector"
        ... )
        >>> print(finding.secret_type, finding.risk_level)
        AWS_ACCESS_KEY_ID RiskLevel.MEDIUM
        >>> d = finding.to_dict()
        >>> print(d['redacted_value'])
        AKIA***MPLE
    """
    file: str
    line: int
    secret_type: str
    value: str
    redacted_value: str
    is_hardcoded: bool  # хардкод или переменная окружения
    context: PipelineContext = field(default_factory=PipelineContext)
    risk_score: float = 5.0  # 0-10
    risk_level: RiskLevel = RiskLevel.MEDIUM
    detected_at: datetime = field(default_factory=datetime.now)
    additional_data: Dict[str, Any] = field(default_factory=dict)
    detector_name: str = "Unknown"

    def to_dict(self) -> dict:
        """
        Конвертирует finding в словарь для JSON-сериализации.

        Используется при экспорте результатов в JSON/SARIF форматы.
        Значение 'value' заменяется на 'redacted_value' для безопасности.

        Returns:
            dict: Словарь с полями finding.
                 Включает вложенный context.to_dict() и summary статистику.

        Example:
            >>> finding = Finding(...)
            >>> d = finding.to_dict()
            >>> print(d['secret_type'], d['risk_score'])
            AWS_ACCESS_KEY_ID 5.0
        """
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
            "detector_name": self.detector_name
        }


@dataclass
class ScanResult:
    """
    Результат сканирования файла или директории.

    Содержит все находки и метаданные сканирования.
    Возвращается методами ScannerEngine.scan_file() и scan_directory().

    Attributes:
        findings (list[Finding]): Список найденных уязвимостей
        files_scanned (int): Количество просканированных файлов
        scan_duration_ms (float): Длительность сканирования в миллисекундах
        ci_systems_detected (list[str]): Список обнаруженных типов CI/CD систем
        errors (list[str]): Список ошибок возникших при сканировании

    Example:
        >>> from scanner.core.models import ScanResult, Finding
        >>> result = ScanResult(
        ...     findings=[finding1, finding2],
        ...     files_scanned=5,
        ...     scan_duration_ms=45.23,
        ...     ci_systems_detected=["gitlab", "github"]
        ... )
        >>> print(f"Found {len(result.findings)} secrets")
        Found 2 secrets
        >>> print(result.has_critical)
        False
        >>> summary = result.to_dict()['summary']
        >>> print(summary['total'])
        2
    """
    findings: list
    files_scanned: int
    scan_duration_ms: float
    ci_systems_detected: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        """
        Конвертирует результат в словарь для JSON-сериализации.

        Returns:
            dict: Словарь с полями результата включая:
                - findings: Список finding.to_dict() для каждого
                - summary: Агрегированная статистика по уровням риска

        Example:
            >>> result = ScanResult(...)
            >>> d = result.to_dict()
            >>> print(d['summary']['critical'])
            1
        """
        return {
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "ci_systems_detected": self.ci_systems_detected,
            "errors": self.errors,
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
        """
        Проверяет наличие критических уязвимостей.

        Используется для определения кода возврата CLI (--fail-on critical).

        Returns:
            bool: True если есть хотя бы одна уязвимость уровня CRITICAL

        Example:
            >>> result = ScanResult(findings=[finding_critical], ...)
            >>> print(result.has_critical)
            True
        """
        return any(f.risk_level == RiskLevel.CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        """
        Проверяет наличие высокоуровневых уязвимостей.

        Используется для определения кода возврата CLI (--fail-on high).

        Returns:
            bool: True если есть хотя бы одна уязвимость уровня HIGH или CRITICAL

        Example:
            >>> result = ScanResult(findings=[finding_high], ...)
            >>> print(result.has_high)
            True
        """
        return any(f.risk_level == RiskLevel.HIGH for f in self.findings)