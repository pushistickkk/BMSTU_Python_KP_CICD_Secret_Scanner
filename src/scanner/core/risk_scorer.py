"""
Risk Scorer — многофакторная оценка риска уязвимостей
"""

from typing import Dict
from scanner.core.models import Finding, RiskLevel, PipelineContext


class ContextAwareRiskScorer:
    """
    Оценка риска на основе контекста пайплайна - Risk = Base(secret_type) × Stage(stage) × Environment(env) × Hardcoded
    
    Где:
        Base(secret_type) в диапазоне [2.0 - 10.0]  # Вес типа секрета
        Stage(stage) в диапазоне [0.5 - 2.0]   # Этап пайплайна
        Environment(env) в диапазоне  [0.7 - 2.0]   # Окружение
        Hardcoded(is_hardcoded) в диапазоне [0.5 - 1.5] # Хардкод vs переменная
    """
    
    # Базовые веса для типов секретов
    SECRET_TYPE_WEIGHTS = {
        "AWS_ACCESS_KEY_ID": 9.0,
        "AWS_SECRET_ACCESS_KEY": 10.0,
        "GITHUB_PAT": 8.0,
        "GITHUB_FINE_GRAINED": 7.0,
        "GITHUB_OAUTH": 8.0,
        "GITLAB_PAT": 8.0,
        "DATABASE_URL": 9.0,
        "PRIVATE_KEY": 10.0,
        "SLACK_TOKEN": 5.0,
        "STRIPE_KEY": 8.0,
        "SENDGRID_KEY": 6.0,
        "GENERIC_PASSWORD": 5.0,
        "GENERIC_TOKEN": 5.0,
    }
    
    # Множители для этапов пайплайна
    STAGE_MULTIPLIERS = {
        "deploy": 2.0,
        "release": 2.0,
        "publish": 2.0,
        "build": 1.0,
        "test": 0.7,
        "lint": 0.5,
        "unknown": 1.0,
    }
    
    # Множители для окружений
    ENVIRONMENT_MULTIPLIERS = {
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
        Вычисляет риск для файндинга.
        Args:
            finding: Объект Finding с контекстом
            
        Returns:
            float: Risk score от 0.0 до 10.0
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
        
        # Множитель за флаг прода
        prod_mult = 1.5 if context.is_production else 1.0
        
        # Множитель за хардкод
        hardcoded_mult = 1.5 if finding.is_hardcoded else 0.5
        
        # Финальный расчёт
        score = base_score * stage_mult * env_mult * prod_mult * hardcoded_mult
        
        # Нормализация до 0-10
        return min(max(score, 0.0), 10.0)
    
    def get_level(self, score: float) -> RiskLevel:
        """
        Определяет уровень риска.
        Args:
            score: Risk score (0.0 - 10.0)
        Returns:
            RiskLevel: LOW, MEDIUM, HIGH, или CRITICAL
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
        Основной метод.
        Вычисляет и обновляет risk_score и risk_level в finding.
        Args:
            finding: Объект Finding
        Returns:
            Finding: Обновлённый объект
        """
        finding.risk_score = self.score(finding)
        finding.risk_level = self.get_level(finding.risk_score)
        return finding