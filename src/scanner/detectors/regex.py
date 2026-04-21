"""
Regex-детектор секретов.

Этот модуль предоставляет класс RegexDetector который ищет известные
паттерны секретов с помощью регулярных выражений и автоматически
фильтрует переменные окружения.

Модуль содержит:
- SECRET_PATTERNS: Словарь компилированных регулярных выражений
- SECRET_RISK_BASE: Базовые веса риска для каждого типа секрета
- VARIABLE_PATTERNS: Паттерны для распознавания переменных окружения
- SAFE_VALUES: Список безопасных заглушек
- Функции is_variable_reference() и redact_value()
- Класс RegexDetector

Пример использования:
    >>> from scanner.detectors.regex import RegexDetector
    >>> detector = RegexDetector()
    >>> findings = detector.detect(config, values)
    >>> for f in findings:
    ...     print(f.secret_type, f.redacted_value)
    AWS_ACCESS_KEY_ID AKIA***MPLE
"""

import re
from typing import List, Dict, Any, Tuple
from scanner.detectors.base import DetectorMixin
from scanner.core.models import Finding, PipelineContext

# ─────────────────────────────────────────────────────────────────────
# ПАТТЕРНЫ СЕКРЕТОВ
# ─────────────────────────────────────────────────────────────────────

SECRET_PATTERNS: Dict[str, re.Pattern] = {
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

# Базовые риски для каждого типа секретов
# Эти значения используются как базовый вес в формуле риск-скоринга
SECRET_RISK_BASE: Dict[str, float] = {
    "AWS_ACCESS_KEY_ID": 6.0,
    "AWS_SECRET_ACCESS_KEY": 7.0,
    "GITHUB_PAT": 5.0,
    "GITHUB_FINE_GRAINED": 4.0,
    "GITHUB_OAUTH": 5.0,
    "GITLAB_PAT": 5.0,
    "DATABASE_URL": 6.0,
    "PRIVATE_KEY": 8.0,
    "SLACK_TOKEN": 3.0,
    "STRIPE_KEY": 5.0,
    "SENDGRID_KEY": 4.0,
    "GENERIC_PASSWORD": 3.0,
    "GENERIC_TOKEN": 3.0,
}


# ПАТТЕРНЫ ПЕРЕМЕННЫХ ОКРУЖЕНИЯ (безопасные ссылки)


VARIABLE_PATTERNS: List[re.Pattern] = [
    re.compile(r'^\$[A-Z_][A-Z0-9_]*$', re.IGNORECASE),  # $VAR
    re.compile(r'^\$\{[A-Z_][A-Z0-9_]*\}$', re.IGNORECASE),  # ${VAR}
    re.compile(r'^\$\{\{\s*secrets\.[A-Z_0-9]+\s*\}\}$', re.IGNORECASE),  # ${{ secrets.* }}
    re.compile(r'^\$\{\{\s*env\.[A-Z_0-9]+\s*\}\}$', re.IGNORECASE),  # ${{ env.* }}
    re.compile(r'^\$\{\{\s*github\.[a-z_]+\s*\}\}$', re.IGNORECASE),  # ${{ github.* }}
    re.compile(r'^\$CI_[A-Z_]+$', re.IGNORECASE),  # $CI_*
]

# Явные безопасные значения (заглушки)
SAFE_VALUES: List[str] = [
    'null', 'none', 'false', 'true', '',
    'changeme', 'placeholder', 'xxx', 'yyy',
    'your_', 'example', 'test', 'demo'
]


def is_variable_reference(value: str) -> bool:
    """
    Проверяет, является ли значение ссылкой на переменную окружения.

    Переменные окружения считаются безопасными и не детектируются как секреты.
    Поддерживаемые форматы:
    - $VAR (GitLab/GitHub)
    - ${VAR} (GitLab)
    - ${{ secrets.* }} (GitHub Actions)
    - ${{ env.* }} (GitHub Actions)
    - ${{ github.* }} (GitHub Actions)
    - $CI_* (GitLab built-in variables)

    Также фильтруются явные заглушки: null, none, false, true, changeme, etc.

    Args:
        value (str): Значение для проверки

    Returns:
        bool: True если это переменная окружения или заглушка (безопасно),
              False если это потенциальный хардкод секрета

    Example:
        >>> is_variable_reference("$AWS_KEY")
        True
        >>> is_variable_reference("${{ secrets.TOKEN }}")
        True
        >>> is_variable_reference("AKIAIOSFODNN7EXAMPLE")
        False
        >>> is_variable_reference("changeme")
        True
    """
    if not isinstance(value, str):
        return False

    value = value.strip()

    # Пустые значения — безопасно
    if not value:
        return True

    # Явные заглушки (ТОЛЬКО точное совпадение, не подстрока!)
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

    for pattern in variable_patterns:
        if re.match(pattern, value, re.IGNORECASE):
            return True

    return False


def redact_value(value: str, visible_chars: int = 4) -> str:
    """
    Маскирует значение секрета для безопасного вывода.

    Используется для предотвращения утечки реальных секретов в логи и отчёты.
    Сохраняет первые и последние visible_chars символов для идентификации.

    Алгоритм:
    - Если длина <= visible_chars * 2: возвращает строку из '*'
    - Иначе: первые visible_chars + '*' * (длина - 2*visible_chars) + последние visible_chars

    Args:
        value (str): Оригинальное значение секрета
        visible_chars (int): Количество видимых символов с каждой стороны (по умолчанию 4)

    Returns:
        str: Замаскированное значение

    Example:
        >>> redact_value("AKIAIOSFODNN7EXAMPLE")
        'AKIA************MPLE'
        >>> redact_value("short", visible_chars=2)
        '*****'
        >>> redact_value("abcdefgh", visible_chars=2)
        'ab****gh'
    """
    if len(value) <= visible_chars * 2:
        return '*' * len(value)
    return value[:visible_chars] + '*' * (len(value) - visible_chars * 2) + value[-visible_chars:]


class RegexDetector(DetectorMixin):
    """
    Детектор секретов на основе регулярных выражений.

    Ищет известные паттерны секретов и автоматически фильтрует переменные окружения.

    Алгоритм работы:
    1. Проходит по всем строковым значениям из конфигурации
    2. Пропускает не-строки и значения короче min_length
    3. Фильтрует переменные окружения через is_variable_reference()
    4. Проверяет каждое значение против SECRET_PATTERNS
    5. При совпадении создаёт Finding с соответствующим secret_type

    Особые случаи:
    - DATABASE_URL: Извлекает только пароль из строки подключения
    - GENERIC_PASSWORD/GENERIC_TOKEN: Извлекает значение из группы захвата

    Attributes:
        min_length (int): Минимальная длина значения для проверки

    Example:
        >>> detector = RegexDetector(min_length=10)
        >>> findings = detector.detect(config, values)
        >>> for f in findings:
        ...     print(f.secret_type, f.redacted_value)
        AWS_ACCESS_KEY_ID AKIA***MPLE
    """

    def __init__(self, min_length: int = 8):
        """
        Инициализирует детектор.

        Args:
            min_length (int): Минимальная длина значения для проверки.
                             Значения короче игнорируются для снижения ложных срабатываний.

        Example:
            >>> detector = RegexDetector(min_length=12)
            >>> print(detector.min_length)
            12
        """
        self.min_length = min_length

    def get_priority(self) -> int:
        """
        Возвращает приоритет выполнения детектора.

        Returns:
            int: 1 (высокий приоритет — выполняется первым)
        """
        return 1

    def detect(
        self,
        config: Any,
        all_values: List[Tuple[str, str, Dict[str, Any]]]
    ) -> List[Finding]:
        """
        Ищет секреты в предоставленных значениях.

        Алгоритм:
        1. Проходит по всем кортежам (key_path, value, context_dict)
        2. Пропускает не-строки и значения короче min_length
        3. Фильтрует переменные окружения (ключевая проверка!)
        4. Проверяет каждое значение против всех SECRET_PATTERNS
        5. При совпадении создаёт Finding с соответствующим secret_type

        Особые случаи обработки:
        - DATABASE_URL: Извлекает только пароль из группы захвата
        - GENERIC_PASSWORD/GENERIC_TOKEN: Извлекает значение из группы захвата

        Args:
            config: Распарсенная конфигурация (используется для file_path)
            all_values (List[tuple]): Список кортежей (key_path, value, context_dict)
                                     где context_dict содержит метаданные (stage, env, etc.)

        Returns:
            List[Finding]: Список найденных уязвимостей

        Example:
            >>> detector = RegexDetector()
            >>> findings = detector.detect(config, values)
            >>> print(f"Found {len(findings)} secrets")
            Found 2 secrets
            >>> for f in findings:
            ...     print(f.secret_type, f.line)
            AWS_ACCESS_KEY_ID 10
            AWS_SECRET_ACCESS_KEY 11
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

                    # Для DATABASE_URL извлекаем пароль из группы захвата
                    if secret_type == "DATABASE_URL" and match.groups():
                        matched_value = f"password={match.group(1)}"

                    # Для GENERIC_* извлекаем значение из группы захвата
                    if secret_type in ["GENERIC_PASSWORD", "GENERIC_TOKEN"] and match.groups():
                        matched_value = match.group(1)

                    # Извлекаем номер строки из context_dict (pop удаляет ключ)
                    line_num = context_dict.pop('line', 0)

                    # Создаём Finding
                    finding = Finding(
                        file=config.file_path,
                        line=line_num,  # Передаём напрямую в Finding
                        secret_type=secret_type,
                        value=matched_value,
                        redacted_value=redact_value(matched_value),
                        is_hardcoded=True,
                        context=PipelineContext(**context_dict),  # Оставшиеся поля контекста
                        risk_score=SECRET_RISK_BASE.get(secret_type, 5.0),
                        detector_name="RegexDetector",
                    )
                    findings.append(finding)

        return findings