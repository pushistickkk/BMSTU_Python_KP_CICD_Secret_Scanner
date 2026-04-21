"""
Базовый класс для всех репортёров.

Этот модуль предоставляет класс-миксин ReporterMixin который реализует
абстрактный интерфейс BaseReporter. Наследование от этого класса
гарантирует что все репортёры имеют одинаковый интерфейс.
"""

from scanner.core.interfaces import BaseReporter


class ReporterMixin(BaseReporter):
    """
    Базовая реализация общих методов репортёров.

    Этот класс определяет контракт для всех репортёров которые
    форматируют и выводят результаты сканирования.

    Поддерживаемые форматы вывода:
    - Console: Красивый вывод в терминал с цветами (Rich)
    - JSON: Машиночитаемый формат для интеграции
    - SARIF: Формат для GitHub Security Tab
    - Text: Plain text для сохранения в файл

    Наследники должны переопределить:
    - report(): Форматирует и выводит результаты

    Example:
        >>> class ConsoleReporter(ReporterMixin):
        ...     def report(self, result, output_path=None):
        ...         # Логика вывода в консоль
        ...         return "Report generated"
    """

    def report(self, result: any, output_path: str | None = None) -> str:
        """
        Форматирует и выводит результаты сканирования.

        Должен быть переопределён в наследниках.

        Преобразует объект ScanResult в строковое представление
        заданного формата и опционально сохраняет в файл.

        Args:
            result (any): Результат сканирования (ScanResult)
            output_path (str | None): Путь для сохранения отчёта.
                                     Если None, вывод только в консоль.

        Returns:
            str: Сформированный отчёт в формате репортёра

        Raises:
            NotImplementedError: Если метод не переопределён
            IOError: Если файл не может быть записан

        Example:
            >>> reporter = ConsoleReporter()
            >>> report = reporter.report(result, 'results/scan.txt')
            >>> print(f"Report saved, {len(report)} bytes")
            Report saved, 2048 bytes
        """
        raise NotImplementedError