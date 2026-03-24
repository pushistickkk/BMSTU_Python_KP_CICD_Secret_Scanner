"""
Console Reporter — вывод результатов в терминал с цветами.
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

        for finding in result.findings:
            # Цвет в зависимости от риска
            if finding.risk_level == RiskLevel.CRITICAL:
                color = "red"
            elif finding.risk_level == RiskLevel.HIGH:
                color = "orange1"
            elif finding.risk_level == RiskLevel.MEDIUM:
                color = "yellow"
            else:
                color = "blue"

            # Формирование информации
            info = [
                f"[{color}] {finding.secret_type}[/bold {color}]",
                f"  File: [cyan]{finding.file}[/cyan]",
                f"  Value: [red]{finding.redacted_value}[/red]",
                f"  Risk Score: [{color}]{finding.risk_score:.1f}[/bold {color}] ({finding.risk_level.value})",
                f"  CI System: {finding.context.ci_system}",
                f"  Stage: {finding.context.stage or 'N/A'}",
                f"  Environment: {finding.context.environment or 'N/A'}",
                f"  Job: {finding.context.job_name or 'N/A'}",
                f"  Hardcoded: {'[red]Yes[/red]' if finding.is_hardcoded else '[green]No[/green]'}",
            ]

            panel = Panel(
                "\n".join(info),
                title=f"Finding #{result.findings.index(finding) + 1}",
                border_style=color,
                padding=(1, 2)
            )

            self.console.print(panel)
            output_lines.append(f"{finding.secret_type} in {finding.file}")

        return "\n".join(output_lines)