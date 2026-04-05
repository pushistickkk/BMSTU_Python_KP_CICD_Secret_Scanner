"""
Format Validators — валидация формата найденных секретов.
Снижает FP через проверку специфичных правил.
"""

from abc import ABC, abstractmethod
from typing import List
from scanner.core.models import Finding
from scanner.core.interfaces import BaseValidator
from scanner.core.risk_scorer import ContextAwareRiskScorer



class BaseFormatValidator(ABC):
    """Базовый класс для валидаторов формата."""
    
    @abstractmethod
    def validate(self, finding: Finding) -> Finding:
        """
        Валидирует формат секрета.
        Args:
            finding: Объект Finding
        Returns:
            Finding: Обновлённый объект (с изменённым risk_score)
        """
        pass


class AWSKeyValidator(BaseFormatValidator):
    """Валидирует формат AWS ключей."""
    
    def validate(self, finding: Finding) -> Finding:
        if finding.secret_type not in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]:
            return finding
        
        value = finding.value
        
        # AWS Access Key ID: всегда начинается с AKIA/ASIA/ABIA/ACCA
        if finding.secret_type == "AWS_ACCESS_KEY_ID":
            if not value.startswith(("AKIA", "ASIA", "ABIA", "ACCA")):
                finding.risk_score *= 0.3
                finding.additional_data["validation_failed"] = "Invalid prefix"
        
        # AWS Secret Key: ровно 40 символов
        if finding.secret_type == "AWS_SECRET_ACCESS_KEY":
            if len(value) != 40:
                finding.risk_score *= 0.3
                finding.additional_data["validation_failed"] = "Invalid length"
        
        # Обновляем уровень риска
        scorer = ContextAwareRiskScorer()
        finding.risk_level = scorer.get_level(finding.risk_score)
        finding.additional_data["validated"] = True
        return finding


class GitHubTokenValidator(BaseFormatValidator):
    """Валидирует формат GitHub токенов."""
    
    def validate(self, finding: Finding) -> Finding:
        if finding.secret_type not in ["GITHUB_PAT", "GITHUB_FINE_GRAINED", "GITHUB_OAUTH"]:
            return finding
        
        value = finding.value
        
        # ghp_ + 36 символов = 40 всего
        if finding.secret_type == "GITHUB_PAT":
            if not (value.startswith("ghp_") and len(value) == 40):
                finding.risk_score *= 0.3
                finding.additional_data["validation_failed"] = "Invalid format"
        
        # github_pat_ + 22 + _ + 59
        if finding.secret_type == "GITHUB_FINE_GRAINED":
            if not value.startswith("github_pat_"):
                finding.risk_score *= 0.3
                finding.additional_data["validation_failed"] = "Invalid prefix"
        

        scorer = ContextAwareRiskScorer()
        finding.risk_level = scorer.get_level(finding.risk_score)
        
        finding.additional_data["validated"] = True
        return finding


class StripeKeyValidator(BaseFormatValidator):
    """Валидирует формат Stripe ключей."""
    
    def validate(self, finding: Finding) -> Finding:
        if finding.secret_type != "STRIPE_KEY":
            return finding
        
        value = finding.value
        
        # sk_live_ или sk_test_ + 24 символа
        if not (value.startswith("sk_live_") or value.startswith("sk_test_")):
            finding.risk_score *= 0.3
            finding.additional_data["validation_failed"] = "Invalid prefix"
        
        if len(value) < 32:
            finding.risk_score *= 0.3
            finding.additional_data["validation_failed"] = "Invalid length"
        

        scorer = ContextAwareRiskScorer()
        finding.risk_level = scorer.get_level(finding.risk_score)
        
        finding.additional_data["validated"] = True
        return finding


class FormatValidatorManager:
    """Управляет всеми валидаторами."""
    
    def __init__(self):
        self.validators: List[BaseFormatValidator] = [
            AWSKeyValidator(),
            GitHubTokenValidator(),
            StripeKeyValidator(),
        ]
    
    def validate(self, finding: Finding) -> Finding:
        """
        Применяет все подходящие валидаторы к находке.
        Args:
            finding: Объект Finding
            
        Returns:
            Finding: Обновлённый объект
        """
        for validator in self.validators:
            finding = validator.validate(finding)
        return finding