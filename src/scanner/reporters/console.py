"""
Console Reporter — вывод результатов в терминал.
"""

from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from scanner.core.models import ScanResult, RiskLevel
from scanner.reporters.base import ReporterMixin


class ConsoleReporter(ReporterMixin):
    """Выводит результаты в консоль с цветным форматированием."""

    def __init__(self):
        self.console = Console()

    def report(self, result: ScanResult, output_path: Path | str | None = None) -> str:
        """
        Форматирует и выводит результаты.

        Args:
            result: Объект ScanResult
            output_path: Путь для сохранения (опционально)

        Returns:
            str: Сформированный отчёт
        """
        if not result.findings:
            return self._no_findings_panel()

        return self._findings_panel(result)

    def _no_findings_panel(self) -> str:
        """Панель когда ничего не найдено."""
        panel = Panel.fit(
            "[green] No secrets detected![/green]",
            title="Scan Complete",
            border_style="green"
        )
        self.console.print(panel)
        return "No secrets detected"

    def _findings_panel(self, result: ScanResult) -> str:
        """Панель с найденными уязвимостями."""
        output_lines = []

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
            output_lines.append(f"{finding.secret_type} in {finding.file}")

        return "\n".join(output_lines)