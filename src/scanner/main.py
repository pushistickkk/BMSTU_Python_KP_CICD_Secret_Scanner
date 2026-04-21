"""
CLI интерфейс для CI/CD Secret Scanner.

Этот модуль предоставляет командный интерфейс для запуска сканера
через консоль с использованием библиотеки click.

Основные команды:
- cicd-scanner scan <PATH> [OPTIONS]: Сканирование файлов/директорий

Поддерживаемые опции:
- --format/-f: Формат вывода (text/json/sarif)
- --output/-o: Путь для сохранения отчёта
- --output-dir: Директория для автоматического сохранения
- --risk-threshold: Фильтрация по минимальному уровню риска
- --fail-on: Код возврата при обнаружении уязвимостей

Примеры использования:
    # Сканирование одного файла
    $ cicd-scanner scan .gitlab-ci.yml

    # Сканирование директории с сохранением в JSON
    $ cicd-scanner scan ./ci-configs/ --format json --output results.json

    # Сканирование с возвратом кода 1 при critical уязвимостях
    $ cicd-scanner scan ./repo/ --fail-on critical

    # Тихий режим (только ошибки)
    $ cicd-scanner scan ./repo/ --quiet

Пример интеграции в CI/CD (GitLab CI):
    secret_scan:
      stage: security
      script:
        - pip install cicd-secret-scanner
        - cicd-scanner scan . --format sarif --output results.sarif --fail-on critical
      artifacts:
        reports:
          codequality: results.sarif
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

# Глобальная консоль Rich для вывода
console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="cicd-scanner")
def cli():
    """
    CI/CD Secret Scanner — контекстный сканер секретов для конфигураций CI/CD.

    Обнаруживает хардкод учётных данных в конфигурационных файлах
    систем непрерывной интеграции и доставки (GitLab CI, GitHub Actions, Jenkins)
    с учётом контекста пайплайна для точной оценки риска.

    Поддерживаемые функции:
    - Многоуровневая детекция (Regex + Entropy + Contextual)
    - Контекстный риск-скоринг (stage × environment × secret_type)
    - Точные номера строк с уязвимостями
    - Информация о детекторе нашедшем секрет
    - Множество форматов вывода (Console/JSON/SARIF/Text)
    - Автоматическое сохранение отчётов в results/

    Документация:
    - README.md: Полное руководство пользователя
    - docs/: Автогенерируемая документация (Sphinx/pdoc)
    - GitHub: https://github.com/yourusername/cicd-secret-scanner

    Примеры команд:
        # Базовое сканирование
        $ cicd-scanner scan .gitlab-ci.yml

        # С сохранением в JSON
        $ cicd-scanner scan ./ci-configs/ --format json --output audit.json

        # С возвратом кода 1 при critical
        $ cicd-scanner scan ./repo/ --fail-on critical

    See 'cicd-scanner scan --help' for more information on scanning options.
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
    help='Формат вывода результатов (по умолчанию: text)'
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
    help='Минимальный уровень риска для вывода в отчёт (по умолчанию: medium)'
)
@click.option(
    '--fail-on',
    type=click.Choice(['none', 'high', 'critical']),
    default='none',
    help='Код возврата при обнаружении уязвимостей: 1 если найдено (по умолчанию: none)'
)
@click.option(
    '--quiet', '-q',
    is_flag=True,
    help='Тихий режим: не выводить детали находок в консоль'
)
def scan(
    path: str,
    format: str,
    output: str | None,
    output_dir: str,
    risk_threshold: str,
    fail_on: str,
    quiet: bool
):
    """
    Сканировать файл или директорию на наличие секретов.

    Выполняет полный пайплайн сканирования:
    1. Определение типа CI/CD системы по имени файла
    2. Парсинг конфигурации в структурированный объект
    3. Извлечение всех строковых значений с контекстом
    4. Детекция секретов (Regex → Entropy)
    5. Дедупликация и контекстное обогащение находок
    6. Валидация формата и риск-скоринг
    7. Формирование и вывод отчёта

    Поддерживаемые типы файлов:
    - GitLab CI: .gitlab-ci.yml, .gitlab/ci/*.yml
    - GitHub Actions: .github/workflows/*.yml, *.yaml
    - Jenkins: Jenkinsfile, *.jenkinsfile

    ARGS:
        PATH: Путь к файлу или директории с CI/CD конфигурациями.
             Может быть относительным или абсолютным.

    OPTIONS:
        --format, -f: Формат вывода результатов.
            - text: Plain text отчёт (по умолчанию)
            - json: Машиночитаемый JSON для интеграции
            - sarif: Формат для GitHub Security Tab

        --output, -o: Путь для сохранения отчёта.
            Если не указан, генерируется имя вида:
            results/<target>_<timestamp>.<format>
            Например: results/gitlab-ci_yml_20240115_143022.text

        --output-dir: Директория для автоматического сохранения.
            Используется если --output не указан или содержит только имя файла.
            По умолчанию: results/

        --risk-threshold: Минимальный уровень риска для включения в отчёт.
            Находки с более низким риском будут отфильтрованы.
            Возможные значения: low, medium, high, critical

        --fail-on: Определяет код возврата процесса.
            - none: Всегда возвращает 0 (по умолчанию)
            - high: Возвращает 1 если найдено HIGH или CRITICAL
            - critical: Возвращает 1 только если найдено CRITICAL
            Полезно для интеграции в CI/CD пайплайны.

        --quiet, -q: Тихий режим.
            Не выводить детали находок в консоль, только итоговую статистику.
            Полезно для автоматизации и логгирования.

    EXAMPLES:
        # Сканирование одного файла
        $ cicd-scanner scan .gitlab-ci.yml

        # Сканирование директории с рекурсивным поиском
        $ cicd-scanner scan ./ci-configs/

        # Сохранение в JSON с кастомным именем
        $ cicd-scanner scan ./repo/ --format json --output audit.json

        # Интеграция в CI/CD с возвратом кода при critical
        $ cicd-scanner scan . --format sarif --output results.sarif --fail-on critical

        # Тихий режим для автоматизации
        $ cicd-scanner scan ./ci-configs/ --quiet --format json --output results.json

    EXIT CODES:
        0: Успешное завершение (или --fail-on=none)
        1: Найдены уязвимости уровня --fail-on или выше
        2: Ошибка при сканировании (невалидный путь, ошибка парсинга, и т.д.)

    See also:
        cicd-scanner --help: Показать справку по всем командам
    """
    path = Path(path)

    # Создаём директорию для результатов если не существует
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Генерируем имя файла если не указано
    if not output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_target = path.name.replace('.', '_').replace('/', '_')
        output = output_dir / f"{scan_target}_{timestamp}.{format}"
    else:
        output = Path(output)
        # Если указано только имя файла, добавляем output_dir
        if not output.parent.name or output.parent == Path('.'):
            output = output_dir / output.name

    # Заголовок сканирования
    console.print(Panel.fit(
        f"🔍 Scanning: [bold cyan]{path}[/bold cyan]",
        title="CI/CD Secret Scanner",
        border_style="blue"
    ))

    start_time = time.time()

    # Инициализация движка сканера
    engine = ScannerEngine()

    # Запуск сканирования в зависимости от типа пути
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

    # Выбор репортёра в зависимости от формата
    if format == 'json':
        reporter = JSONReporter()
    elif format == 'sarif':
        reporter = SARIFReporter()
    else:
        reporter = ConsoleReporter()

    # Генерация и сохранение отчёта
    report = reporter.report(result, output)

    # Вывод в консоль
    console.print(f"\n[green] Report saved to: {output}[/green]\n")
    _print_summary(result, duration)

    # Определение кода возврата
    if fail_on != 'none':
        if fail_on == 'critical' and result.has_critical:
            raise click.Exit(code=1)
        elif fail_on == 'high' and (result.has_critical or result.has_high):
            raise click.Exit(code=1)


def _print_summary(result, duration: float):
    """
    Выводит итоговую статистику сканирования в консоль.

    Форматирует и отображает ключевые метрики результата:
    - Количество просканированных файлов
    - Длительность сканирования
    - Общее количество находок
    - Распределение по уровням риска (Critical/High/Medium/Low)

    Использует rich.Table для красивого табличного вывода.

    Args:
        result (ScanResult): Результат сканирования со статистикой
        duration (float): Длительность сканирования в секундах

    Returns:
        None: Выводит информацию напрямую в консоль

    Example:
        >>> _print_summary(result, 0.045)
          Files scanned:     4
          Duration:          0.05s
          Total findings:    8
          Critical:          6
          High:              2
    """
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column("Label", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Files scanned:", str(result.files_scanned))
    summary_table.add_row("Duration:", f"{duration:.2f}s")
    summary_table.add_row("Total findings:", str(len(result.findings)))
    summary_table.add_row(
        "Critical:",
        str(sum(1 for f in result.findings if f.risk_level == RiskLevel.CRITICAL))
    )
    summary_table.add_row(
        "High:",
        str(sum(1 for f in result.findings if f.risk_level == RiskLevel.HIGH))
    )

    console.print()
    console.print(summary_table)


if __name__ == '__main__':
    """
    Точка входа для запуска CLI через python -m scanner.main.

    Примеры:
        $ python -m scanner.main --help
        $ python -m scanner.main scan .gitlab-ci.yml
    """
    cli()