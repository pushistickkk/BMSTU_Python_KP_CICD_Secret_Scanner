"""
Console Reporter — вывод результатов в терминал с цветами.
Использует rich для красивого форматирования.
"""

from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from scanner.core.models import ScanResult, RiskLevel
from scanner.reporters.base import ReporterMixin


class ConsoleReporter(ReporterMixin):
    """Выводит результаты в консоль с цветным форматированием."""
    
    def __init__(self):
        self.console = Console()
    
    def report(self, result: ScanResult, output_path: Path | str | None = None) -> str:
        """
        Форматирует и выводит результаты.
        
        - В консоль: красивые Rich панели с цветами
        - В файл: plain text отчёт (без ANSI кодов)
        """
        #  Генерируем plain text отчёт для файла
        report_text = self._generate_text_report(result)
        
        #  Сохранение в файл
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_text)
        
        #  Вывод в консоль через Rich
        self._print_rich_console(result)
        
        return report_text
    
    def _generate_text_report(self, result: ScanResult) -> str:
        """Генерирует plain text отчёт для файла (без ANSI кодов)."""
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
        """Выводит красивые панели Rich в консоль."""
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