"""
JSON Reporter — вывод результатов в формате JSON. - НЕ ДОДЕЛАН, типо заглушка
"""

import json
from pathlib import Path
from scanner.core.models import ScanResult
from scanner.reporters.base import ReporterMixin


class JSONReporter(ReporterMixin):
    """Выводит результаты в формате JSON."""

    def report(self, result: ScanResult, output_path: Path | str | None = None) -> str:
        """
        Форматирует и выводит результаты в JSON.

        Args:
            result: Объект ScanResult
            output_path: Путь для сохранения (опционально)

        Returns:
            str: JSON строка
        """
        data = result.to_dict()
        json_str = json.dumps(data, indent=2, ensure_ascii=False)

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)

        return json_str