"""
Contextual Detector — добавление доп инфы к находкам.
"""

from typing import List, Dict, Any, Tuple
from scanner.detectors.base import DetectorMixin
from scanner.core.models import Finding
from scanner.core.risk_scorer import ContextAwareRiskScorer


class ContextualDetector(DetectorMixin):
    """
    Детектор для контекста к уязам.
    - Применяет риск-скоринг
    - Добавляет контекстные правила
    - Фильтрует по окружению
    """
    
    def __init__(self):
        self.scorer = ContextAwareRiskScorer()
    
    def get_priority(self) -> int:
        """Выполняется после regex детектора."""
        return 2
    
    def detect(
                self, 
                config: Any, 
                all_values: List[Tuple[str, str, Dict[str, Any]]]
            ) -> List[Finding]:
        """
        Этот детектор не используется напрямую.
        Вызываем apply_context() для контекста.
        """
        return []
    
    def apply_context(self, findings: List[Finding]) -> List[Finding]:
        """
        Применяет контекстный анализ к найденным секретам.
        Args:
            findings: Список файндингов от других детекторов            
        Returns:
            Список с risk_score и risk_level
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
        Args:
            finding: Объект Finding
        Returns:
            Finding: Обновлённый объект
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
        Args:
            image: Docker image name
        Returns:
            bool: True если публичный
        """
        public_registries = ['docker.io', 'hub.docker.com', 'gcr.io']
        return any(r in image.lower() for r in public_registries) and 'private' not in image.lower()