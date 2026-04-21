"""
JSON Reporter — вывод результатов в формате JSON.

Этот модуль предоставляет класс JSONReporter который преобразует
результаты сканирования в машиночитаемый JSON формат.

Особенности:
- Полная сериализация ScanResult через to_dict()
- Поддержка кириллицы (ensure_ascii=False)
- Красивое форматирование (indent=2)
- Автоматическое создание директорий при сохранении

Пример использования:
    >>> from scanner.reporters.json import JSONReporter
    >>> reporter = JSONReporter()
    >>> json_output = reporter.report(result, 'results/scan.json')
    >>> import json
    >>> data = json.loads(json_output)
    >>> print(f"Found {data['summary']['total']} secrets")
"""

import json
from pathlib import Path
from scanner.core.models import ScanResult
from scanner.reporters.base import ReporterMixin


class JSONReporter(ReporterMixin):
    """
    Репортёр для вывода результатов в формате JSON.

    Преобразует объект ScanResult в JSON строку используя метод
    to_dict() всех вложенных моделей (Finding, PipelineContext).

    Особенности формата:
    - Все значения маскируются через redacted_value для безопасности
    - Временные метки в ISO 8601 формате
    - Числовые значения округлены до 2 знаков после запятой
    - Поддержка кириллицы в путях и именах

    Пример структуры вывода:
    {
        "findings": [...],
        "files_scanned": 5,
        "scan_duration_ms": 45.23,
        "ci_systems_detected": ["gitlab", "github"],
        "errors": [],
        "summary": {
            "total": 8,
            "hardcoded": 8,
            "critical": 6,
            "high": 2,
            "medium": 0,
            "low": 0
        }
    }

    Example:
        >>> reporter = JSONReporter()
        >>> json_str = reporter.report(result)
        >>> print(json_str[:100])
        {
          "findings": [
            {
              "file": ".gitlab-ci.yml",
              "line": 10,
    """

    def report(self, result: ScanResult, output_path: Path | str | None = None) -> str:
        """
        Форматирует и выводит результаты в формате JSON.

        Алгоритм:
        1. Преобразует ScanResult в словарь через result.to_dict()
        2. Сериализует в JSON строку с форматированием
        3. Если указан output_path — сохраняет в файл с созданием директорий
        4. Возвращает JSON строку

        Args:
            result (ScanResult): Результат сканирования содержащий
                               список находок и метаданные
            output_path (Path | str | None): Путь для сохранения отчёта.
                                           Если None, возвращает только строку.

        Returns:
            str: JSON строка с результатами сканирования

        Raises:
            IOError: Если файл не может быть записан
            PermissionError: Если нет прав на запись в директорию
            OSError: Если не удалось создать родительские директории

        Example:
            >>> reporter = JSONReporter()
            >>> json_str = reporter.report(result, 'results/scan.json')
            >>> print(f"Generated {len(json_str)} bytes of JSON")
            Generated 4096 bytes of JSON
            >>> import json
            >>> data = json.loads(json_str)
            >>> print(data['summary']['critical'])
            6
        """
        # Преобразуем результат в словарь
        data = result.to_dict()

        # Сериализуем в JSON с форматированием
        json_str = json.dumps(data, indent=2, ensure_ascii=False)

        # Сохранение в файл если указан путь
        if output_path:
            output_path = Path(output_path)
            # Автоматически создаём родительские директории
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)

        return json_str