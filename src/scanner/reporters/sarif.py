"""
SARIF Reporter — вывод в формате для GitHub Security.

Этот модуль предоставляет класс SARIFReporter который генерирует
отчёты в формате SARIF 2.1.0 (Static Analysis Results Interchange Format).

SARIF — это стандартный формат для обмена результатами статического анализа
который поддерживается:
- GitHub Security Tab (Code Scanning)
- Azure DevOps Security Alerts
- Visual Studio Code Problems pane
- Другие инструменты статического анализа

Документация стандарта:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Пример использования:
    >>> from scanner.reporters.sarif import SARIFReporter
    >>> reporter = SARIFReporter()
    >>> sarif_output = reporter.report(result, 'results/scan.sarif')
    >>> # Загрузить в GitHub:
    >>> # uses: github/codeql-action/upload-sarif@v2
    >>> # with: sarif_file: results/scan.sarif
"""

import json
from pathlib import Path
from scanner.core.models import ScanResult, RiskLevel
from scanner.reporters.base import ReporterMixin


class SARIFReporter(ReporterMixin):
    """
    Репортёр для генерации отчётов в формате SARIF 2.1.0.

    SARIF (Static Analysis Results Interchange Format) — это открытый стандарт
    для обмена результатами статического анализа кода.

    Структура SARIF отчёта:
    {
        "$schema": "https://.../sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { ... } },
            "results": [ ... ]
        }]
    }

    Каждая находка преобразуется в SARIF result с полями:
    - ruleId: Идентификатор правила (тип секрета)
    - level: Уровень серьёзности (error/warning/note)
    - message: Текст сообщения об уязвимости
    - locations: Позиция в файле (артефакт + регион)
    - properties: Дополнительные метаданные (riskScore, detector, ciSystem)

    Интеграция с GitHub Actions:
    ```yaml
    - name: Upload SARIF to GitHub Security
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: results/scan.sarif
    ```

    Example:
        >>> reporter = SARIFReporter()
        >>> sarif_str = reporter.report(result, 'results/scan.sarif')
        >>> import json
        >>> data = json.loads(sarif_str)
        >>> print(data['runs'][0]['results'][0]['ruleId'])
        AWS_ACCESS_KEY_ID
    """

    def report(self, result: ScanResult, output_path: Path | str | None = None) -> str:
        """
        Генерирует отчёт в формате SARIF 2.1.0.

        Алгоритм:
        1. Создаёт структуру SARIF с метаданными инструмента
        2. Генерирует правила через _generate_rules()
        3. Преобразует находки в SARIF results через _generate_results()
        4. Сериализует в JSON строку
        5. Если указан output_path — сохраняет в файл

        Формат выходных данных соответствует спецификации:
        https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

        Args:
            result (ScanResult): Результат сканирования содержащий
                               список находок и метаданные
            output_path (Path | str | None): Путь для сохранения .sarif файла.
                                           Если None, возвращает только строку.

        Returns:
            str: JSON строка в формате SARIF 2.1.0

        Raises:
            IOError: Если файл не может быть записан
            PermissionError: Если нет прав на запись в директорию

        Example:
            >>> reporter = SARIFReporter()
            >>> sarif_str = reporter.report(result, 'results/scan.sarif')
            >>> import json
            >>> data = json.loads(sarif_str)
            >>> print(data['version'])
            2.1.0
            >>> print(len(data['runs'][0]['results']))
            8
        """
        # Основная структура SARIF отчёта
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CI/CD Secret Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/yourusername/cicd-secret-scanner",
                        "rules": self._generate_rules(),
                    }
                },
                "results": self._generate_results(result),
            }]
        }

        # Сериализация в JSON
        output = json.dumps(sarif, indent=2, ensure_ascii=False)

        # Сохранение в файл если указан путь
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output)

        return output

    def _generate_rules(self) -> list[dict]:
        """
        Генерирует список правил (rules) для SARIF отчёта.

        Каждое правило описывает тип обнаруживаемой уязвимости:
        - id: Уникальный идентификатор правила
        - name: Человекочитаемое название
        - shortDescription: Краткое описание проблемы
        - defaultConfiguration: Уровень серьёзности по умолчанию

        Поддерживаемые правила:
        - AWS_CREDENTIALS: Учётные данные AWS
        - GITHUB_TOKEN: Токены доступа GitHub
        - DATABASE_URL: Строки подключения к базам данных

        Примечание: Этот список можно расширять добавлением новых правил
        для каждого типа секрета из SECRET_PATTERNS.

        Returns:
            list[dict]: Список словарей с описанием правил SARIF

        Example:
            >>> reporter = SARIFReporter()
            >>> rules = reporter._generate_rules()
            >>> print(rules[0]['id'])
            AWS_CREDENTIALS
            >>> print(rules[0]['defaultConfiguration']['level'])
            error
        """
        return [
            {
                "id": "AWS_CREDENTIALS",
                "name": "AWS Credentials",
                "shortDescription": {"text": "Hardcoded AWS credentials detected"},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "GITHUB_TOKEN",
                "name": "GitHub Token",
                "shortDescription": {"text": "Hardcoded GitHub token detected"},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "DATABASE_URL",
                "name": "Database Connection String",
                "shortDescription": {"text": "Hardcoded database credentials"},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "PRIVATE_KEY",
                "name": "Private Key",
                "shortDescription": {"text": "Hardcoded private key detected"},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "API_KEY",
                "name": "API Key",
                "shortDescription": {"text": "Hardcoded API key detected"},
                "defaultConfiguration": {"level": "warning"},
            },
        ]

    def _generate_results(self, result: ScanResult) -> list[dict]:
        """
        Преобразует находки сканера в формат SARIF results.

        Для каждой находки создаётся SARIF result со следующими полями:
        - ruleId: Сопоставляется с id правила из _generate_rules()
        - level: "error" для CRITICAL, "warning" для остальных
        - message: Текст сообщения об уязвимости
        - locations: Позиция в файле (artifactLocation + region)
        - properties: Дополнительные метаданные:
            - riskScore: Числовая оценка риска
            - detector: Название детектора нашедшего секрет
            - ciSystem: Тип CI/CD системы

        Формат региона (region):
        {
            "startLine": номер_строки,  # 1-based индекс
            "startColumn": 1,  # Начало строки (упрощённо)
            "endLine": номер_строки,
            "endColumn": длина_значения  # Упрощённо
        }

        Args:
            result (ScanResult): Результат сканирования со списком находок

        Returns:
            list[dict]: Список SARIF results для включения в отчёт

        Example:
            >>> reporter = SARIFReporter()
            >>> results = reporter._generate_results(scan_result)
            >>> print(results[0]['ruleId'])
            AWS_ACCESS_KEY_ID
            >>> print(results[0]['locations'][0]['physicalLocation']['region']['startLine'])
            10
        """
        results = []

        for finding in result.findings:
            # Определение уровня серьёзности
            level = "error" if finding.risk_level == RiskLevel.CRITICAL else "warning"

            sarif_result = {
                "ruleId": finding.secret_type,
                "level": level,
                "message": {
                    "text": f"Hardcoded {finding.secret_type} detected in CI/CD configuration"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file,
                            "uriBaseId": "%SRCROOT%"  # Для GitHub compatibility
                        },
                        "region": {
                            "startLine": finding.line if finding.line > 0 else 1,
                            "startColumn": 1,
                            "endLine": finding.line if finding.line > 0 else 1,
                            # Примечание: точные column позиции требуют парсинга YAML с позициями
                        }
                    }
                }],
                "properties": {
                    "riskScore": finding.risk_score,
                    "riskLevel": finding.risk_level.value,
                    "detector": finding.detector_name,
                    "ciSystem": finding.context.ci_system,
                    "stage": finding.context.stage,
                    "environment": finding.context.environment,
                    "isHardcoded": finding.is_hardcoded,
                },
            }

            # Добавляем snippet если есть содержимое строки
            if finding.context.get('script_content'):
                sarif_result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": finding.context['script_content'][:100]  # Обрезаем для безопасности
                }

            results.append(sarif_result)

        return results