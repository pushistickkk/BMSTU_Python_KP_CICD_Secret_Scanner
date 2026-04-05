"""
Regex-детектор секретов.
Ищет известные паттерны секретов и фильтрует переменные окружения.
"""

import re
from typing import List, Dict, Any, Tuple
from scanner.detectors.base import DetectorMixin
from scanner.core.models import Finding, PipelineContext

# ПАТТЕРНЫ СЕКРЕТОВ - вынести в отдельный файл с правилами для секретов

SECRET_PATTERNS = {
    # AWS Credentials
    "AWS_ACCESS_KEY_ID": re.compile(
        r'(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}',
        re.IGNORECASE
    ),
    "AWS_SECRET_ACCESS_KEY": re.compile(
        r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'
    ),

    # GitHub Tokens
    "GITHUB_PAT": re.compile(
        r'ghp_[A-Za-z0-9]{36}',
        re.IGNORECASE
    ),
    "GITHUB_FINE_GRAINED": re.compile(
        r'github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}',
        re.IGNORECASE
    ),
    "GITHUB_OAUTH": re.compile(
        r'gho_[A-Za-z0-9]{36}',
        re.IGNORECASE
    ),

    # GitLab Tokens
    "GITLAB_PAT": re.compile(
        r'glpat-[A-Za-z0-9\-]{20,}',
        re.IGNORECASE
    ),

    # Database URLs
    "DATABASE_URL": re.compile(
        r'(?:postgres|postgresql|mysql|mongodb|redis)://[^:]+:([^@]+)@[^\s]+',
        re.IGNORECASE
    ),

    # Private Keys
    "PRIVATE_KEY": re.compile(
        r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----',
        re.IGNORECASE
    ),

    # API Keys
    "SLACK_TOKEN": re.compile(
        r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
        re.IGNORECASE
    ),
    "STRIPE_KEY": re.compile(
        r'sk_live_[0-9a-zA-Z]{24}',
        re.IGNORECASE
    ),
    "SENDGRID_KEY": re.compile(
        r'SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}',
        re.IGNORECASE
    ),

    # Generic Secrets
    "GENERIC_PASSWORD": re.compile(
        r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?',
        re.IGNORECASE
    ),
    "GENERIC_TOKEN": re.compile(
        r'(?:token|api_key|apikey)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?',
        re.IGNORECASE
    ),
}

# Базовые риски для каждого типа - приблизительно - вынести в отдельный файл с правилами для секретов
SECRET_RISK_BASE = {
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

# ПАТТЕРНЫ ПЕРЕМЕННЫХ ОКРУЖЕНИЯ

VARIABLE_PATTERNS = [
    re.compile(r'^\$[A-Z_][A-Z0-9_]*$', re.IGNORECASE),           # $VAR
    re.compile(r'^\$\{[A-Z_][A-Z0-9_]*\}$', re.IGNORECASE),       # ${VAR}
    re.compile(r'^\$\{\{\s*secrets\.[A-Z_0-9]+\s*\}\}$', re.IGNORECASE),  # ${{ secrets.* }}
    re.compile(r'^\$\{\{\s*env\.[A-Z_0-9]+\s*\}\}$', re.IGNORECASE),      # ${{ env.* }}
    re.compile(r'^\$\{\{\s*github\.[a-z_]+\s*\}\}$', re.IGNORECASE),      # ${{ github.* }}
    re.compile(r'^\$CI_[A-Z_]+$', re.IGNORECASE),                 # $CI_*
]

# Явные безопасные значения
SAFE_VALUES = [
    'null', 'none', 'false', 'true', '',
    'changeme', 'placeholder', 'xxx', 'yyy',
    'your_', 'example', 'test', 'demo'
]


def is_variable_reference(value: str) -> bool:
    """
    Проверяет, является ли значение ссылкой на переменную окружения. - по $

    Returns:
        True если это переменная (безопасно), False если хардкод
    """
    if not isinstance(value, str):
        return False

    value = value.strip()

    # Пустые значения — безопасно
    if not value:
        return True

    # Явные заглушки (точное совпадение, не подстрока!)
    safe_exact = {'null', 'none', 'false', 'true', '', 'changeme', 'placeholder'}
    if value.lower() in safe_exact:
        return True

    # Проверка паттернов переменных (должно начинаться с $ или ${{)
    variable_patterns = [
        r'^\$[A-Z_][A-Z0-9_]*$',  # $VAR
        r'^\$\{[A-Z_][A-Z0-9_]*\}$',  # ${VAR}
        r'^\$\{\{\s*secrets\.[A-Z_0-9]+\s*\}\}$',  # ${{ secrets.* }}
        r'^\$\{\{\s*env\.[A-Z_0-9]+\s*\}\}$',  # ${{ env.* }}
        r'^\$\{\{\s*github\.[a-z_]+\s*\}\}$',  # ${{ github.* }}
        r'^\$CI_[A-Z_]+$',  # $CI_*
    ]

    for pattern in variable_patterns: # фильтрация FP
        if re.match(pattern, value, re.IGNORECASE):
            return True

    return False


def redact_value(value: str, visible_chars: int = 4) -> str:
    """
    Маскирует значение секрета для безопасного вывода, чтобы в секреты не утекли в логи.

    Args:
        value: Оригинальное значение
        visible_chars: Количество видимых символов с каждой стороны

    Returns:
        Замаскированное значение
    """
    if len(value) <= visible_chars * 2:
        return '*' * len(value)
    return value[:visible_chars] + '*' * (len(value) - visible_chars * 2) + value[-visible_chars:]


class RegexDetector(DetectorMixin):
    """
    Детектор секретов на основе регулярных выражений.

    Ищет известные паттерны секретов и автоматически
    фильтрует переменные окружения.
    """

    def __init__(self, min_length: int = 8):
        """
        Инициализирует детектор.

        Args:
            min_length: Минимальная длина значения для проверки
        """
        self.min_length = min_length

    def get_priority(self) -> int:
        """Высокий приоритет — выполняется первым."""
        return 1

    def detect(
        self,
        config: Any,
        all_values: List[Tuple[str, str, Dict[str, Any]]]
    ) -> List[Finding]:
        """
        Ищет секреты в предоставленных значениях.

        Args:
            config: Распарсенная конфигурация (GitLabCIConfig)
            all_values: Список (key_path, value, context_dict)

        Returns:
            Список объектов Finding
        """
        findings = []

        for key_path, value, context_dict in all_values:
            # Пропускаем не-строки и слишком короткие значения
            if not isinstance(value, str) or len(value) < self.min_length:
                continue

            # КЛЮЧЕВАЯ ПРОВЕРКА: фильтруем переменные окружения
            if is_variable_reference(value):
                continue  # Это переменная, а не хардкод

            # Проверяем каждый паттерн
            for secret_type, pattern in SECRET_PATTERNS.items():
                match = pattern.search(value)
                if match:
                    # Извлекаем найденное значение
                    matched_value = match.group(0)

                    # Для DATABASE_URL извлекаем пароль из группы
                    if secret_type == "DATABASE_URL" and match.groups():
                        matched_value = f"password={match.group(1)}"

                    # Для GENERIC_* извлекаем значение из группы
                    if secret_type in ["GENERIC_PASSWORD", "GENERIC_TOKEN"] and match.groups():
                        matched_value = match.group(1)

                    # Создаём Finding
                    finding = Finding(
                        file=config.file_path,
                        line=0,  # нужно добавить определение номера строки
                        secret_type=secret_type,
                        value=matched_value,
                        redacted_value=redact_value(matched_value),
                        is_hardcoded=True,
                        context=PipelineContext(**context_dict),
                        risk_score=SECRET_RISK_BASE.get(secret_type, 5.0),
                        detector_name="RegexDetector",
                    )
                    findings.append(finding)

        return findings