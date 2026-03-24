"""Тесты для Regex детектора."""

import pytest
from scanner.parsers.gitlab import GitLabParser
from scanner.detectors.regex import RegexDetector, is_variable_reference


@pytest.fixture
def detector():
    return RegexDetector()


@pytest.fixture
def parser():
    return GitLabParser()


def test_detector_finds_aws_keys(detector, parser):
    """Проверяет обнаружение AWS ключей."""
    config = parser.parse("tests/fixtures/vulnerable/gitlab_aws.yml")
    values = parser.get_all_values_with_context(config)
    findings = detector.detect(config, values)

    assert len(findings) >= 2
    assert any(f.secret_type == "AWS_ACCESS_KEY_ID" for f in findings)
    assert any(f.secret_type == "AWS_SECRET_ACCESS_KEY" for f in findings)


def test_detector_ignores_variables(detector, parser):
    """Проверяет игнорирование переменных окружения."""
    config = parser.parse("tests/fixtures/safe/gitlab_vars.yml")
    values = parser.get_all_values_with_context(config)
    findings = detector.detect(config, values)

    assert len(findings) == 0


def test_is_variable_reference():
    """Проверяет функцию определения переменных."""
    # Переменные
    assert is_variable_reference("$VAR") == True
    assert is_variable_reference("${VAR}") == True
    assert is_variable_reference("${{ secrets.TOKEN }}") == True
    assert is_variable_reference("$CI_JOB_TOKEN") == True

    # Хардкод
    assert is_variable_reference("AKIAIOSFODNN7EXAMPLE") == False
    assert is_variable_reference("mysecret123") == False


def test_detector_risk_score(detector, parser):
    """Проверяет расчёт risk_score."""
    config = parser.parse("tests/fixtures/vulnerable/gitlab_aws.yml")
    values = parser.get_all_values_with_context(config)
    findings = detector.detect(config, values)

    for finding in findings:
        assert finding.risk_score >= 5.0
        assert finding.risk_score <= 10.0