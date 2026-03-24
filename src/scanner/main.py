"""
CLI интерфейс для CI/CD Secret Scanner.
Использует click для парсинга аргументов командной строки.
"""

import click
import time
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from scanner.core.engine import ScannerEngine
from scanner.core.models import RiskLevel
from scanner.reporters.console import ConsoleReporter
from scanner.reporters.json import JSONReporter

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="cicd-scanner")
def cli():
    """
    CI/CD Secret Scanner — контекстный сканер секретов для конфигураций CI/CD.
    Поддерживает GitLab CI.
    """
    pass


@cli.command()
@click.argument(
    'path',
    type=click.Path(exists=True),
    required=True
)
@click.option(
    '--format', '-f',
    type=click.Choice(['text', 'json']),
    default='text',
    help='Формат вывода результатов: text, json'
)
@click.option(
    '--output', '-o',
    type=click.Path(),
    default=None,
    help='Путь для сохранения отчёта'
)
@click.option(
    '--risk-threshold',
    type=click.Choice(['low', 'medium', 'high', 'critical']),
    default='medium',
    help='Минимальный уровень риска для вывода - по умолчанию Medium'
)
@click.option(
    '--fail-on',
    type=click.Choice(['none', 'high', 'critical']),
    default='none',
    help='Код возврата при обнаружении уязвимостей'
)
def scan(path, format, output, risk_threshold, fail_on):
    """
    Сканировать файл или директорию на наличие секретов.

    PATH: Путь к файлу или директории с CI/CD конфигурациями
    """
    path = Path(path)

    console.print(Panel.fit(
        f"🔍 Scanning: [bold cyan]{path}[/bold cyan]",
        title="CI/CD Secret Scanner",
        border_style="blue"
    ))

    start_time = time.time()

    # Инициализация движка
    engine = ScannerEngine()

    # Сканирование
    if path.is_file():
        result = engine.scan_file(path)
    elif path.is_dir():
        result = engine.scan_directory(path)
    else:
        console.print("[red] Invalid path![/red]")
        return

    duration = time.time() - start_time

    # Вывод результатов
    if format == 'json':
        reporter = JSONReporter()
    else:
        reporter = ConsoleReporter()

    report = reporter.report(result, output)

    # Печать отчёта
    if not output:
        console.print(report)

    # Итоговая статистика
    _print_summary(result, duration)

    # Код возврата
    if fail_on != 'none':
        if fail_on == 'critical' and result.has_critical:
            raise click.Exit(code=1)
        elif fail_on == 'high' and (result.has_critical or result.has_high):
            raise click.Exit(code=1)


def _print_summary(result, duration: float):
    """Выводит итоговую статистику."""
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column("Label", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Files scanned:", str(result.files_scanned))
    summary_table.add_row("Duration:", f"{duration:.2f}s")
    summary_table.add_row("Total findings:", str(len(result.findings)))
    summary_table.add_row("Critical:", str(sum(1 for f in result.findings if f.risk_level == RiskLevel.CRITICAL)))
    summary_table.add_row("High:", str(sum(1 for f in result.findings if f.risk_level == RiskLevel.HIGH)))

    console.print()
    console.print(summary_table)


if __name__ == '__main__':
    cli()