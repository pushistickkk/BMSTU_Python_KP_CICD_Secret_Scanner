"""Тесты для Risk Scorer"""

import pytest
from scanner.core.risk_scorer import ContextAwareRiskScorer
from scanner.core.models import Finding, PipelineContext, RiskLevel


@pytest.fixture
def scorer():
    return ContextAwareRiskScorer()


def test_aws_key_in_prod_deploy(scorer):
    finding = Finding(
        file="test.yml",
        line=10,
        secret_type="AWS_SECRET_ACCESS_KEY",
        value="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        redacted_value="wJal***EKEY",
        is_hardcoded=True,
        context=PipelineContext(
            ci_system="gitlab",
            stage="deploy",
            environment="production",
            is_production=True,
        )
    )
    
    score = scorer.score(finding)
    level = scorer.get_level(score)
    
    assert score >= 9.0
    assert level == RiskLevel.CRITICAL


def test_secret_in_test_stage(scorer):
    finding = Finding(
        file="test.yml",
        line=10,
        secret_type="GITHUB_PAT",
        value="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        redacted_value="ghp_x***xxx",
        is_hardcoded=True,
        context=PipelineContext(
            ci_system="github",
            stage="test",
            environment="test",
            is_production=False,
        )
    )
    
    score = scorer.score(finding)
    level = scorer.get_level(score)
    
    assert score <= 6.0
    assert level in [RiskLevel.LOW, RiskLevel.MEDIUM]


def test_score_normalization(scorer):
    finding = Finding(
        file="test.yml",
        line=10,
        secret_type="GENERIC_TOKEN",
        value="test123",
        redacted_value="tes***23",
        is_hardcoded=False,
        context=PipelineContext(
            ci_system="gitlab",
            stage="lint",
            environment="dev",
            is_production=False,
        )
    )
    
    score = scorer.score(finding)
    
    assert 0.0 <= score <= 10.0