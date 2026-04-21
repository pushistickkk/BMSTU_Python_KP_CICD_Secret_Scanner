"""
Contextual Detector — обогащение находок контекстной информацией.

Этот модуль предоставляет класс ContextualDetector который:
- Применяет риск-скоринг к найденным секретам
- Добавляет контекстные правила для корректировки риска
- Фильтрует находки по окружению

Важно: Этот детектор не ищет новые секреты, а улучшает существующие находки.
"""

from typing import List, Dict, Any, Tuple
from scanner.detectors.base import DetectorMixin
from scanner.core.models import Finding
from scanner.core.risk_scorer import ContextAwareRiskScorer


class ContextualDetector(DetectorMixin):
    """
    Детектор для контекстного обогащения найденных секретов.

    Этот детектор работает на этапе пост-обработки:
    1. Принимает список Finding от других детекторов
    2. Применяет риск-скоринг через ContextAwareRiskScorer
    3. Применяет дополнительные контекстные правила
    4. Возвращает обогащённый список находок

    Контекстные правила:
    - Правило 1: Секрет в deploy + production = +1.0 к риску (макс. 10.0)
    - Правило 2: Секрет в публичном Docker image = +0.5 к риску
    - Правило 3: Секрет в test-джобе (не production) = -1.0 к риску (мин. 1.0)

    Attributes:
        scorer (ContextAwareRiskScorer): Экземпляр риск-скорера

    Example:
        >>> detector = ContextualDetector()
        >>> enhanced = detector.apply_context(findings)
        >>> for f in enhanced:
        ...     print(f.secret_type, f.risk_score, f.risk_level)
        AWS_SECRET_ACCESS_KEY 10.0 RiskLevel.CRITICAL
    """

    def __init__(self):
        """
        Инициализирует контекстный детектор.

        Создаёт экземпляр ContextAwareRiskScorer для вычисления риска.
        """
        self.scorer = ContextAwareRiskScorer()

    def get_priority(self) -> int:
        """
        Возвращает приоритет выполнения детектора.

        Returns:
            int: 2 (средний приоритет — выполняется после RegexDetector)
        """
        return 2

    def detect(
        self,
        config: Any,
        all_values: List[Tuple[str, str, Dict[str, Any]]]
    ) -> List[Finding]:
        """
        Метод детекции (не используется напрямую).

        Этот детектор работает через метод apply_context(), а не detect().
        Метод detect() возвращает пустой список для совместимости с интерфейсом.

        Args:
            config: Распарсенная конфигурация (не используется)
            all_values: Список значений (не используется)

        Returns:
            List[Finding]: Пустой список
        """
        return []

    def apply_context(self, findings: List[Finding]) -> List[Finding]:
        """
        Применяет контекстный анализ к найденным секретам.

        Это основной метод детектора который:
        1. Проходит по всем находкам
        2. Применяет риск-скоринг через scorer.score_and_update()
        3. Применяет дополнительные контекстные правила
        4. Возвращает обогащённый список

        Args:
            findings (List[Finding]): Список находок от других детекторов

        Returns:
            List[Finding]: Список находок с обновлёнными risk_score и risk_level

        Example:
            >>> detector = ContextualDetector()
            >>> enhanced = detector.apply_context(findings)
            >>> print(enhanced[0].risk_level)
            RiskLevel.CRITICAL
        """
        enhanced_findings = []

        for finding in findings:
            # Применяем риск-скоринг
            finding = self.scorer.score_and_update(finding)

            # Применяем дополнительные контекстные правила
            finding = self._apply_context_rules(finding)

            enhanced_findings.append(finding)

        return enhanced_findings

    def _apply_context_rules(self, finding: Finding) -> Finding:
        """
        Применяет дополнительные правила на основе контекста.

        Правила корректируют риск после базового скоринга:
        - deploy + production: +1.0 (макс. 10.0)
        - Публичный Docker image: +0.5 (макс. 10.0)
        - test stage (не production): -1.0 (мин. 1.0)

        После корректировки пересчитывается risk_level.

        Args:
            finding (Finding): Объект Finding для обновления

        Returns:
            Finding: Обновлённый объект с скорректированным риском

        Example:
            >>> detector = ContextualDetector()
            >>> finding = Finding(context=PipelineContext(stage="deploy", is_production=True))
            >>> updated = detector._apply_context_rules(finding)
            >>> print(updated.risk_score)
            10.0
        """
        context = finding.context

        # Правило 1: Секрет в deploy + production = CRITICAL
        if context.stage == 'deploy' and context.is_production:
            finding.risk_score = min(finding.risk_score + 1.0, 10.0)
            finding.risk_level = self.scorer.get_level(finding.risk_score)

        # Правило 2: Секрет в публичном image = повысить риск
        if context.image and self._is_public_image(context.image):
            finding.risk_score = min(finding.risk_score + 0.5, 10.0)
            finding.risk_level = self.scorer.get_level(finding.risk_score)

        # Правило 3: Секрет в test-джобе = снизить риск
        if context.stage == 'test' and not context.is_production:
            finding.risk_score = max(finding.risk_score - 1.0, 1.0)
            finding.risk_level = self.scorer.get_level(finding.risk_score)

        return finding

    def _is_public_image(self, image: str) -> bool:
        """
        Проверяет, является ли Docker image публичным.

        Публичные реестры: docker.io, hub.docker.com, gcr.io
        Изображения со словом 'private' в имени считаются приватными.

        Args:
            image (str): Имя Docker image

        Returns:
            bool: True если image из публичного реестра

        Example:
            >>> detector = ContextualDetector()
            >>> detector._is_public_image("nginx:latest")
            True
            >>> detector._is_public_image("private-registry.com/app:1.0")
            False
        """
        public_registries = ['docker.io', 'hub.docker.com', 'gcr.io']
        return any(r in image.lower() for r in public_registries) and 'private' not in image.lower()