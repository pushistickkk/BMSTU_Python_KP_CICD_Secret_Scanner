"""
Console Reporter — вывод результатов в терминал с цветами.

Этот модуль предоставляет класс ConsoleReporter который использует
библиотеку rich для красивого форматирования вывода в консоль.

Особенности:
- Цветные панели с иконками для разных уровней риска
- Таблицы для итоговой статистики
- Одновременный вывод в консоль и сохранение в файл

Пример использования:
    >>> from scanner.reporters.console import ConsoleReporter
    >>> reporter = ConsoleReporter()
    >>> report = reporter.report(result, 'results/scan.txt')
    >>> print(f"Console report generated, {len(report)} bytes")
"""

from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from scanner.core.models import ScanResult, RiskLevel
from scanner.reporters.base import ReporterMixin


class ConsoleReporter(ReporterMixin):
    """
    Репортёр для вывода результатов в консоль с цветным форматированием.

    Использует библиотеку rich для создания:
    - Панелей с границами и заголовками
    - Цветного текста для разных уровней риска
    - Таблиц для итоговой статистики

    Поддерживает два режима вывода:
    1. В консоль: Красивые Rich панели с цветами и иконками
    2. В файл: Plain text без ANSI кодов для совместимости

    Attributes:
        console (rich.console.Console): Экземпляр консоли rich

    Example:
        >>> reporter = ConsoleReporter()
        >>> report = reporter.report(result)
        >>> # Вывод в консоль с цветами
        >>> report = reporter.report(result, 'results/scan.txt')
        >>> # Вывод в консоль + сохранение в файл
    """

    def __init__(self):
        """
        Инициализирует консольный репортёр.

        Создаёт экземпляр rich.Console для форматированного вывода.
        """
        self.console = Console()

    def report(self, result: ScanResult, output_path: Path | str | None = None) -> str:
        """
        Форматирует и выводит результаты сканирования.

        Генерирует два формата отчёта:
        1. Plain text для сохранения в файл (без ANSI кодов)
        2. Rich панели для вывода в консоль (с цветами)

        Алгоритм:
        1. Генерирует plain text отчёт через _generate_text_report()
        2. Если указан output_path — сохраняет plain text в файл
        3. Выводит Rich панели в консоль через _print_rich_console()
        4. Возвращает plain text отчёт

        Args:
            result (ScanResult): Результат сканирования
            output_path (Path | str | None): Путь для сохранения отчёта

        Returns:
            str: Plain text отчёт (без ANSI кодов)

        Example:
            >>> reporter = ConsoleReporter()
            >>> report = reporter.report(result, 'results/scan.txt')
            >>> print(report[:100])
            ============================================================
        """
        # Генерируем plain text отчёт для файла
        report_text = self._generate_text_report(result)

        # Сохранение в файл
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_text)

        # Вывод в консоль через Rich (красивые панели)
        self._print_rich_console(result)

        return report_text

    def _generate_text_report(self, result: ScanResult) -> str:
        """
        Генерирует plain text отчёт для сохранения в файл.

        Формат отчёта:
        - Заголовок с разделителями
        - Список находок с полями (без цветов)
        - Итоговая статистика в табличном виде

        Этот метод не использует rich и не добавляет ANSI коды,
        что делает отчёт совместимым с любым текстовым редактором.

        Args:
            result (ScanResult): Результат сканирования

        Returns:
            str: Plain text отчёт (без ANSI кодов)

        Example:
            >>> reporter = ConsoleReporter()
            >>> text = reporter._generate_text_report(result)
            >>> print(text[:200])
            ============================================================
            CI/CD SECRET SCANNER - SCAN REPORT
        """
        lines = []
        lines.append("=" * 60)
        lines.append("CI/CD SECRET SCANNER - SCAN REPORT")
        lines.append("=" * 60)
        lines.append("")

        if not result.findings:
            lines.append(" No secrets detected!")
            lines.append("")
        else:
            for i, finding in enumerate(result.findings):
                # Текстовые метки вместо цветов
                if finding.risk_level == RiskLevel.CRITICAL:
                    icon = "[CRITICAL]"
                elif finding.risk_level == RiskLevel.HIGH:
                    icon = "[HIGH]"
                elif finding.risk_level == RiskLevel.MEDIUM:
                    icon = "[MEDIUM]"
                else:
                    icon = "[LOW]"

                lines.append(f"{'=' * 60}")
                lines.append(f"Finding #{i + 1}")
                lines.append(f"{'=' * 60}")
                lines.append(f"  {icon} {finding.secret_type}")
                lines.append(f"  File: {finding.file}")
                lines.append(f"  Line: {finding.line if finding.line > 0 else 'N/A'}")
                lines.append(f"  Value: {finding.redacted_value}")
                lines.append(f"  Risk Score: {finding.risk_score:.1f} ({finding.risk_level.value})")
                lines.append(f"  Detector: {finding.detector_name}")
                lines.append(f"  CI System: {finding.context.ci_system}")
                lines.append(f"  Stage: {finding.context.stage or 'N/A'}")
                lines.append(f"  Environment: {finding.context.environment or 'N/A'}")
                lines.append(f"  Job: {finding.context.job_name or 'N/A'}")
                lines.append(f"  Hardcoded: {'Yes' if finding.is_hardcoded else 'No'}")
                lines.append("")

        # Итоговая статистика
        lines.append("=" * 60)
        lines.append("SUMMARY")
        lines.append("=" * 60)
        lines.append(f"  Files scanned:     {result.files_scanned}")
        lines.append(f"  Duration:          {result.scan_duration_ms / 1000:.2f}s")
        lines.append(f"  Total findings:    {len(result.findings)}")
        lines.append(f"  Critical:          {sum(1 for f in result.findings if f.risk_level == RiskLevel.CRITICAL)}")
        lines.append(f"  High:              {sum(1 for f in result.findings if f.risk_level == RiskLevel.HIGH)}")
        lines.append(f"  Medium:            {sum(1 for f in result.findings if f.risk_level == RiskLevel.MEDIUM)}")
        lines.append(f"  Low:               {sum(1 for f in result.findings if f.risk_level == RiskLevel.LOW)}")
        lines.append("=" * 60)

        return "\n".join(lines)

    def _print_rich_console(self, result: ScanResult):
        """
        Выводит результаты в консоль с цветным форматированием Rich.

        Формат вывода:
        - Панель заголовка сканирования
        - Отдельная панель для каждой находки с:
            - Цветной иконкой по уровню риска
            - Цветным текстом для важных полей
            - Границами и отступами для читаемости
        - Таблица итоговой статистики

        Цветовая схема по уровню риска:
        - Красный: CRITICAL (score >= 8.5)
        - Оранжевый: HIGH (score >= 6.5)
        - Жёлтый: MEDIUM (score >= 4.0)
        - Синий: LOW (score < 4.0)

        Args:
            result (ScanResult): Результат сканирования

        Example:
            >>> reporter = ConsoleReporter()
            >>> reporter._print_rich_console(result)
            # Выводит цветные панели в терминал
        """
        if not result.findings:
            panel = Panel.fit(
                "[green] No secrets detected![/green]",
                title="Scan Complete",
                border_style="green"
            )
            self.console.print(panel)
            return

        for i, finding in enumerate(result.findings):
            # Цвет в зависимости от риска
            if finding.risk_level == RiskLevel.CRITICAL:
                color = "red"
            elif finding.risk_level == RiskLevel.HIGH:
                color = "orange1"
            elif finding.risk_level == RiskLevel.MEDIUM:
                color = "yellow"
            else:
                color = "blue"

            info = [
                f"[{color} bold] {finding.secret_type}[/{color} bold]",
                f"[cyan]File:[/cyan] {finding.file}",
                f"[cyan]Line:[/cyan] {finding.line if finding.line > 0 else 'N/A'}",
                f"[cyan]Value:[/cyan] [{color}]{finding.redacted_value}[/{color}]",
                f"[cyan]Risk Score:[/cyan] [{color} bold]{finding.risk_score:.1f}[/bold {color}] ({finding.risk_level.value})",
                f"[cyan]Detector:[/cyan] {finding.detector_name}",
                f"[cyan]CI System:[/cyan] {finding.context.ci_system}",
                f"[cyan]Stage:[/cyan] {finding.context.stage or 'N/A'}",
                f"[cyan]Environment:[/cyan] {finding.context.environment or 'N/A'}",
                f"[cyan]Job:[/cyan] {finding.context.job_name or 'N/A'}",
                f"[cyan]Hardcoded:[/cyan] [{'red' if finding.is_hardcoded else 'green'}]{'Yes' if finding.is_hardcoded else 'No'}[/{'red' if finding.is_hardcoded else 'green'}]",
            ]

            panel = Panel(
                "\n".join(info),
                title=f"Finding #{i + 1}",
                border_style=color,
                padding=(1, 2)
            )

            self.console.print(panel)