"""
CLI интерфейс для CI/CD Secret Scanner.
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
from scanner.reporters.sarif import SARIFReporter

from datetime import datetime

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="cicd-scanner")
def cli():
    """
    CI/CD Secret Scanner — контекстный сканер секретов для конфигураций CI/CD.
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
    type=click.Choice(['text', 'json', 'sarif']),
    default='text',
    help='Формат вывода результатов'
)
@click.option(
    '--output', '-o',
    type=click.Path(),
    default=None,
    help='Путь для сохранения отчёта (по умолчанию: results/<timestamp>.<format>)'
)
@click.option(
    '--output-dir',
    type=click.Path(),
    default='results',
    help='Директория для сохранения отчётов (по умолчанию: results/)'
)
@click.option(
    '--risk-threshold',
    type=click.Choice(['low', 'medium', 'high', 'critical']),
    default='medium',
    help='Минимальный уровень риска для вывода'
)
@click.option(
    '--fail-on',
    type=click.Choice(['none', 'high', 'critical']),
    default='none',
    help='Код возврата при обнаружении уязвимостей'
)
def scan(path, format, output, output_dir, risk_threshold, fail_on):
    """
    Сканировать файл или директорию на наличие секретов.
    
    PATH: Путь к файлу или директории с CI/CD конфигурациями
    """
    path = Path(path)
    
    #  Создаём директорию для результатов
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    #  Если output не указан, генерируем имя файла с timestamp
    if not output:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_target = path.name.replace('.', '_')
        output = output_dir / f"{scan_target}_{timestamp}.{format}"
    else:
        output = Path(output)
        if not output.parent.name or output.parent == Path('.'):
            output = output_dir / output.name
    
    console.print(Panel.fit(
        f" Scanning: [bold cyan]{path}[/bold cyan]",
        title="CI/CD Secret Scanner",
        border_style="blue"
    ))
    
    start_time = time.time()
    
    # Инициализация движка
    engine = ScannerEngine()
    
    # Сканирование
    if path.is_file():
        console.print(f"[dim]Mode: Single file scan[/dim]\n")
        result = engine.scan_file(path)
    elif path.is_dir():
        console.print(f"[dim]Mode: Directory scan (recursive)[/dim]\n")
        result = engine.scan_directory(path)
    else:
        console.print("[red] Invalid path![/red]")
        return
    
    duration = time.time() - start_time
    
    # Выбор репортёра
    if format == 'json':
        reporter = JSONReporter()
    elif format == 'sarif':
        reporter = SARIFReporter()
    else:
        reporter = ConsoleReporter()
    
    #  Генерируем и сохраняем отчёт
    report = reporter.report(result, output)
    
    #  Вывод в консоль
    console.print(f"\n[green] Report saved to: {output}[/green]\n")
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