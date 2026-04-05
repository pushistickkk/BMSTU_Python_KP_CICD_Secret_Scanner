"""Тесты для GitHub Actions парсера
pytest tests/test_github_parser.py tests/test_risk_scorer.py -v
"""

import pytest
from scanner.parsers.github import GitHubParser


@pytest.fixture
def parser():
    return GitHubParser()


def test_parser_get_type(parser):
    assert parser.get_type() == "github"


def test_parser_parse_file(parser):
    config = parser.parse("tests/fixtures/vulnerable/github_workflow.yml")
    
    assert config.file_path.endswith("github_workflow.yml")
    assert len(config.jobs) >= 1
    assert "AWS_SECRET_ACCESS_KEY" in config.global_env


def test_parser_extract_values(parser):
    config = parser.parse("tests/fixtures/vulnerable/github_workflow.yml")
    values = parser.get_all_values_with_context(config)
    
    assert len(values) >= 3
    
    for key_path, value, context in values:
        assert "ci_system" in context
        assert context["ci_system"] == "github"


def test_infer_stage(parser):
    assert parser._infer_stage("deploy_prod", {}) == "deploy"
    assert parser._infer_stage("test_unit", {}) == "test"
    assert parser._infer_stage("build_app", {}) == "build"
    assert parser._infer_stage("custom_job", {}) == "unknown"
