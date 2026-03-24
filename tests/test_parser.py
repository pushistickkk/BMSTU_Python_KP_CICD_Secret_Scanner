"""Тесты для GitLab парсера."""

import pytest
from pathlib import Path
from scanner.parsers.gitlab import GitLabParser


@pytest.fixture
def parser():
    return GitLabParser()


def test_parser_get_type(parser):
    """Проверяет тип CI системы."""
    assert parser.get_type() == "gitlab"


def test_parser_parse_file(parser):
    """Проверяет парсинг файла."""
    config = parser.parse("tests/fixtures/vulnerable/gitlab_aws.yml")

    assert config.file_path.endswith("gitlab_aws.yml")
    assert len(config.jobs) >= 2  # build и deploy_prod
    assert "AWS_ACCESS_KEY_ID" in config.global_vars


def test_parser_extract_values(parser):
    """Проверяет извлечение значений с контекстом."""
    config = parser.parse("tests/fixtures/vulnerable/gitlab_aws.yml")
    values = parser.get_all_values_with_context(config)

    assert len(values) >= 5  # Минимум 5 значений

    # Проверяем что контекст заполнен
    for key_path, value, context in values:
        assert "ci_system" in context
        assert context["ci_system"] == "gitlab"


def test_parser_safe_file(parser):
    """Проверяет парсинг безопасного файла."""
    config = parser.parse("tests/fixtures/safe/gitlab_vars.yml")
    values = parser.get_all_values_with_context(config)

    # Проверяем что глобальные переменные — это ссылки
    var_values = [
        value for key_path, value, ctx
        in values
        if ctx.get('section') in ['global_variables', 'job_variables']
    ]

    for value in var_values:
        # Переменные должны начинаться с $ или ${{
        assert value.startswith('$') or value.startswith('${'), f"Unexpected value: {value}"