"""Проверка что проект правильно инициализирован."""


def test_imports():
    """Проверяет что все модули импортируются."""
    from scanner.core import models, interfaces
    from scanner.core.models import Finding, ScanResult, RiskLevel, PipelineContext
    from scanner.core.interfaces import BaseParser, BaseDetector, BaseValidator, BaseReporter

    assert Finding is not None
    assert ScanResult is not None
    assert RiskLevel is not None
    assert PipelineContext is not None
    assert BaseParser is not None
    assert BaseDetector is not None
    assert BaseValidator is not None
    assert BaseReporter is not None


def test_models():
    """Проверяет что модели работают."""
    from scanner.core.models import Finding, PipelineContext, RiskLevel

    context = PipelineContext(
        ci_system="gitlab",
        stage="deploy",
        is_production=True
    )

    finding = Finding(
        file="test.yml",
        line=10,
        secret_type="AWS_ACCESS_KEY_ID",
        value="AKIAIOSFODNN7EXAMPLE",
        redacted_value="AKIA***MPLE",
        is_hardcoded=True,
        context=context,
        risk_score=9.0,
        risk_level=RiskLevel.CRITICAL
    )

    assert finding.to_dict() is not None
    assert finding.context.ci_system == "gitlab"
    assert finding.risk_level == RiskLevel.CRITICAL