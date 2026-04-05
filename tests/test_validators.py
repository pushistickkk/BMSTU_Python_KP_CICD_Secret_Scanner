"""Тесты для Format Validators"""

import pytest
from scanner.validators.format import AWSKeyValidator, GitHubTokenValidator, FormatValidatorManager
from scanner.core.models import Finding, PipelineContext, RiskLevel


@pytest.fixture
def aws_validator():
    return AWSKeyValidator()


@pytest.fixture
def github_validator():
    return GitHubTokenValidator()


def test_aws_key_validator_valid(aws_validator):
    """Проверяет валидацию валидного AWS ключа."""
    finding = Finding(
        file="test.yml",
        line=1,
        secret_type="AWS_ACCESS_KEY_ID",
        value="AKIAIOSFODNN7EXAMPLE",
        redacted_value="AKIA***MPLE",
        is_hardcoded=True,
        context=PipelineContext(),
        risk_score=9.0
    )
    
    result = aws_validator.validate(finding)
    assert result.risk_score == 9.0  # Не изменился
    assert result.additional_data.get("validated") == True


def test_aws_key_validator_invalid(aws_validator):
    """Проверяет валидацию невалидного AWS ключа."""
    finding = Finding(
        file="test.yml",
        line=1,
        secret_type="AWS_ACCESS_KEY_ID",
        value="INVALID_KEY_FORMAT",
        redacted_value="INVA***MAT",
        is_hardcoded=True,
        context=PipelineContext(),
        risk_score=9.0
    )
    
    result = aws_validator.validate(finding)
    assert result.risk_score < 9.0  # Снижен
    assert result.additional_data.get("validation_failed") is not None


def test_github_token_validator(github_validator):
    """Проверяет валидацию GitHub токена."""
    finding = Finding(
        file="test.yml",
        line=1,
        secret_type="GITHUB_PAT",
        value="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        redacted_value="ghp_x***xxx",
        is_hardcoded=True,
        context=PipelineContext(),
        risk_score=8.0
    )
    
    result = github_validator.validate(finding)
    assert result.risk_score == 8.0  # Валидный
    assert result.additional_data.get("validated") == True


def test_validator_manager():
    """Проверяет менеджер валидаторов."""
    manager = FormatValidatorManager()
    
    finding = Finding(
        file="test.yml",
        line=1,
        secret_type="AWS_ACCESS_KEY_ID",
        value="AKIAIOSFODNN7EXAMPLE",
        redacted_value="AKIA***MPLE",
        is_hardcoded=True,
        context=PipelineContext(),
        risk_score=9.0
    )
    
    result = manager.validate(finding)
    assert result.additional_data.get("validated") == True