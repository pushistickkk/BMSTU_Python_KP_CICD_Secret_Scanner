"""
Risk Scorer — многофакторная оценка риска уязвимостей.

Этот модуль предоставляет класс ContextAwareRiskScorer для вычисления
уровня риска на основе контекста CI/CD пайплайна.

Формула расчёта:
    Risk = Base(secret_type) × Stage(stage) × Environment(env) × Hardcoded

Где:
    - Base(secret_type): Вес типа секрета [2.0 - 10.0]
    - Stage(stage): Множитель этапа пайплайна [0.5 - 2.0]
    - Environment(env): Множитель окружения [0.7 - 2.0]
    - Hardcoded(is_hardcoded): Множитель хардкода [0.5 - 1.5]

Пример использования:
    >>> from scanner.core.risk_scorer import ContextAwareRiskScorer
    >>> from scanner.core.models import Finding, PipelineContext
    >>> scorer = ContextAwareRiskScorer()
    >>> finding = Finding(
    ...     file="test.yml",
    ...     line=10,
    ...     secret_type="AWS_SECRET_ACCESS_KEY",
    ...     value="secret",
    ...     redacted_value="sec***t",
    ...     is_hardcoded=True,
    ...     context=PipelineContext(stage="deploy", environment="production")
    ... )
    >>> updated = scorer.score_and_update(finding)
    >>> print(finding.risk_score, finding.risk_level)
    10.0 RiskLevel.CRITICAL
"""

from typing import Dict
from scanner.core.models import Finding, RiskLevel, PipelineContext


class ContextAwareRiskScorer:
    """
    Оценка риска на основе контекста пайплайна.

    Использует многофакторную формулу для вычисления риска:
    - Base(secret_type): Вес типа секрета [2.0 - 10.0]
    - Stage(stage): Множитель этапа пайплайна [0.5 - 2.0]
    - Environment(env): Множитель окружения [0.7 - 2.0]
    - Hardcoded(is_hardcoded): Множитель хардкода [0.5 - 1.5]

    Дополнительно применяется множитель ×1.5 для is_production=True,
    что позволяет ещё больше повысить риск для production окружений.

    Итоговый score нормализуется в диапазон [0.0, 10.0].

    Класс содержит три публичных метода:
    - score(): Вычисляет числовой риск
    - get_level(): Конвертирует score в категориальный уровень
    - score_and_update(): Основной метод для использования в пайплайне

    Attributes:
        SECRET_TYPE_WEIGHTS (dict): Базовые веса для типов секретов
        STAGE_MULTIPLIERS (dict): Множители для этапов пайплайна
        ENVIRONMENT_MULTIPLIERS (dict): Множители для окружений

    Example:
        >>> scorer = ContextAwareRiskScorer()
        >>> finding = Finding(
        ...     file="test.yml",
        ...     line=10,
        ...     secret_type="AWS_SECRET_ACCESS_KEY",
        ...     value="secret",
        ...     redacted_value="sec***t",
        ...     is_hardcoded=True,
        ...     context=PipelineContext(stage="deploy", environment="production")
        ... )
        >>> updated = scorer.score_and_update(finding)
        >>> print(finding.risk_score)
        10.0
        >>> print(finding.risk_level)
        RiskLevel.CRITICAL
    """

    # Базовые веса для типов секретов
    # Диапазон: 3.0 (низкий) - 8.0 (критический)
    SECRET_TYPE_WEIGHTS: Dict[str, float] = {
        "AWS_ACCESS_KEY_ID": 6.0,
        "AWS_SECRET_ACCESS_KEY": 7.0,
        "GITHUB_PAT": 5.0,
        "GITHUB_FINE_GRAINED": 4.0,
        "GITHUB_OAUTH": 5.0,
        "GITLAB_PAT": 5.0,
        "DATABASE_URL": 6.0,
        "PRIVATE_KEY": 8.0,
        "SLACK_TOKEN": 3.0,
        "STRIPE_KEY": 5.0,
        "SENDGRID_KEY": 4.0,
        "GENERIC_PASSWORD": 3.0,
        "GENERIC_TOKEN": 3.0,
    }

    # Множители для этапов пайплайна
    # deploy/release = критично, test/lint = менее критично
    STAGE_MULTIPLIERS: Dict[str, float] = {
        "deploy": 2.0,
        "release": 2.0,
        "publish": 2.0,
        "build": 1.0,
        "test": 0.7,
        "lint": 0.5,
        "unknown": 1.0,
    }

    # Множители для окружений
    # production = критично, dev/test = менее критично
    ENVIRONMENT_MULTIPLIERS: Dict[str, float] = {
        "production": 2.0,
        "prod": 2.0,
        "main": 1.8,
        "master": 1.8,
        "staging": 1.3,
        "stage": 1.3,
        "development": 0.7,
        "dev": 0.7,
        "test": 0.5,
        "": 1.0,
    }

    def score(self, finding: Finding) -> float:
        """
        Вычисляет риск для найденной уязвимости.

        Применяет многофакторную формулу:
            Risk = Base × Stage × Environment × Production × Hardcoded

        Args:
            finding (Finding): Объект Finding с контекстом пайплайна

        Returns:
            float: Risk score в диапазоне [0.0, 10.0] (нормализованный)

        Example:
            >>> scorer = ContextAwareRiskScorer()
            >>> finding = Finding(
            ...     secret_type="AWS_SECRET_ACCESS_KEY",
            ...     is_hardcoded=True,
            ...     context=PipelineContext(stage="deploy", environment="production")
            ... )
            >>> score = scorer.score(finding)
            >>> print(f"{score:.2f}")
            10.00
        """
        context = finding.context

        # Базовый вес типа секрета
        base_score = self.SECRET_TYPE_WEIGHTS.get(finding.secret_type, 5.0)

        # Множитель за этап пайплайна
        stage = context.stage.lower() if context.stage else "unknown"
        stage_mult = self.STAGE_MULTIPLIERS.get(stage, 1.0)

        # Множитель за окружение
        env = context.environment.lower() if context.environment else ""
        env_mult = self.ENVIRONMENT_MULTIPLIERS.get(env, 1.0)

        # Множитель за флаг production
        prod_mult = 1.5 if context.is_production else 1.0

        # Множитель за хардкод
        hardcoded_mult = 1.5 if finding.is_hardcoded else 0.5

        # Финальный расчёт
        score = base_score * stage_mult * env_mult * prod_mult * hardcoded_mult

        # Нормализация до диапазона [0.0, 10.0]
        return min(max(score, 0.0), 10.0)

    def get_level(self, score: float) -> RiskLevel:
        """
        Определяет уровень риска по числовому значению.

        Пороги:
            - >= 8.5: CRITICAL (критический)
            - >= 6.5: HIGH (высокий)
            - >= 4.0: MEDIUM (средний)
            - < 4.0:  LOW (низкий)

        Args:
            score (float): Risk score в диапазоне [0.0, 10.0]

        Returns:
            RiskLevel: Категориальный уровень риска

        Example:
            >>> scorer = ContextAwareRiskScorer()
            >>> print(scorer.get_level(9.0))
            RiskLevel.CRITICAL
            >>> print(scorer.get_level(7.0))
            RiskLevel.HIGH
            >>> print(scorer.get_level(5.0))
            RiskLevel.MEDIUM
            >>> print(scorer.get_level(2.0))
            RiskLevel.LOW
        """
        if score >= 8.5:
            return RiskLevel.CRITICAL
        elif score >= 6.5:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def score_and_update(self, finding: Finding) -> Finding:
        """
        Вычисляет и обновляет risk_score и risk_level в finding.

        Это основной метод для использования в пайплайне сканера.
        Модифицирует объект finding inplace и возвращает его же.

        Алгоритм:
            1. Вычисляет score через self.score()
            2. Определяет level через self.get_level()
            3. Обновляет поля finding
            4. Возвращает тот же объект

        Args:
            finding (Finding): Объект Finding для обновления

        Returns:
            Finding: Тот же объект Finding с обновлёнными полями
                    (для возможности цепочки вызовов)

        Example:
            >>> scorer = ContextAwareRiskScorer()
            >>> finding = Finding(
            ...     secret_type="AWS_SECRET_ACCESS_KEY",
            ...     is_hardcoded=True,
            ...     context=PipelineContext(stage="deploy", environment="production")
            ... )
            >>> updated = scorer.score_and_update(finding)
            >>> assert updated is finding  # Тот же объект
            >>> print(finding.risk_score, finding.risk_level)
            10.0 RiskLevel.CRITICAL
        """
        finding.risk_score = self.score(finding)
        finding.risk_level = self.get_level(finding.risk_score)
        return finding