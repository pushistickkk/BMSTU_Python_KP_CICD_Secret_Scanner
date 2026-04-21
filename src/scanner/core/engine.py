"""
Scanner Engine — оркестратор пайплайна сканирования.

Этот модуль предоставляет класс ScannerEngine, который координирует работу
всех компонентов сканера: парсеров, детекторов, валидаторов и риск-скорера.

Архитектура пайплайна:
    1. Определение типа CI/CD системы (GitLab/GitHub)
    2. Парсинг конфигурационного файла
    3. Извлечение значений с контекстом
    4. Детекция секретов (Regex → Entropy)
    5. Дедупликация находок
    6. Контекстное обогащение и риск-скоринг
    7. Валидация формата
    8. Формирование результата

Пример использования:
    >>> engine = ScannerEngine()
    >>> result = engine.scan_file(".gitlab-ci.yml")
    >>> print(f"Found {len(result.findings)} secrets")
    2

    >>> result = engine.scan_directory("./ci-configs/")
    >>> print(f"Scanned {result.files_scanned} files")
    5
"""

import time
from pathlib import Path
from typing import List

from scanner.core.models import ScanResult
from scanner.core.risk_scorer import ContextAwareRiskScorer

# Парсеры
from scanner.parsers.gitlab import GitLabParser
from scanner.parsers.github import GitHubParser

# Детекторы
from scanner.detectors.regex import RegexDetector
from scanner.detectors.entropy import EntropyDetector
from scanner.detectors.contextual import ContextualDetector

# Валидаторы
from scanner.validators.format import FormatValidatorManager


class ScannerEngine:
    """
    Основной движок сканера секретов.

    Координирует работу всех компонентов сканера:
    - Парсеры: GitLab CI, GitHub Actions
    - Детекторы: RegexDetector, EntropyDetector
    - ContextualDetector: Контекстное обогащение и риск-скоринг
    - FormatValidatorManager: Валидация формата секретов

    Attributes:
        parsers (dict): Словарь парсеров по типу CI/CD системы
        detectors (list): Список детекторов отсортированный по приоритету
        contextual_detector (ContextualDetector): Детектор для контекстного обогащения
        scorer (ContextAwareRiskScorer): Скорер для оценки риска
        validator_manager (FormatValidatorManager): Менеджер валидаторов формата

    Example:
        >>> engine = ScannerEngine()
        >>> result = engine.scan_file(".gitlab-ci.yml")
        >>> print(f"Files: {result.files_scanned}, Findings: {len(result.findings)}")
        Files: 1, Findings: 2
    """

    def __init__(self):
        """
        Инициализирует движок сканера.

        Создаёт и настраивает все необходимые компоненты:
        - Парсеры для GitLab и GitHub
        - Детекторы (Regex, Entropy)
        - Контекстный детектор
        - Риск-скорер
        - Менеджер валидаторов
        """
        self.parsers = {
            'gitlab': GitLabParser(),
            'github': GitHubParser(),
        }
        self.detectors = [
            RegexDetector(),
            EntropyDetector()
        ]
        self.contextual_detector = ContextualDetector()
        self.scorer = ContextAwareRiskScorer()
        self.validator_manager = FormatValidatorManager()

    def _detect_ci_system(self, file_path: Path) -> str:
        """
        Определяет тип CI/CD системы по пути к файлу.

        Анализирует имя файла и путь для определения типа CI/CD системы.
        Поддерживает GitLab CI (.gitlab-ci.yml) и GitHub Actions (.github/workflows/).

        Args:
            file_path (Path): Путь к файлу конфигурации

        Returns:
            str: Тип CI/CD системы ('gitlab', 'github')

        Raises:
            None: Всегда возвращает строку (gitlab по умолчанию)

        Example:
            >>> engine = ScannerEngine()
            >>> system = engine._detect_ci_system(Path(".gitlab-ci.yml"))
            >>> print(system)
            'gitlab'
            >>> system = engine._detect_ci_system(Path(".github/workflows/deploy.yml"))
            >>> print(system)
            'github'
        """
        path_lower = file_path.name.lower()

        if 'gitlab-ci' in path_lower or path_lower.endswith('.gitlab-ci.yml'):
            return 'gitlab'
        elif '.github' in str(file_path) or 'github' in path_lower:
            return 'github'
        else:
            return 'gitlab'  # По умолчанию

    def scan_file(self, file_path: Path | str) -> ScanResult:
        """
        Сканирует один файл на наличие секретов.

        Выполняет полный пайплайн сканирования:
        1. Определение типа CI/CD системы
        2. Парсинг файла
        3. Извлечение значений с контекстом
        4. Детекция секретов (все детекторы по приоритету)
        5. Дедупликация находок
        6. Контекстное обогащение
        7. Валидация формата
        8. Формирование результата

        Args:
            file_path (Path | str): Путь к файлу для сканирования

        Returns:
            ScanResult: Результат сканирования содержащий:
                - findings: Список найденных уязвимостей
                - files_scanned: Количество просканированных файлов (1)
                - scan_duration_ms: Длительность сканирования в миллисекундах
                - ci_systems_detected: Список обнаруженных CI/CD систем
                - errors: Список ошибок (если возникли)

        Raises:
            Exception: Любые исключения при сканировании перехватываются
                      и возвращаются в поле errors результата

        Example:
            >>> engine = ScannerEngine()
            >>> result = engine.scan_file(".gitlab-ci.yml")
            >>> print(f"Found {len(result.findings)} secrets in {result.scan_duration_ms:.2f}ms")
            Found 2 secrets in 15.23ms
        """
        file_path = Path(file_path)
        start = time.time()

        # Определяем CI-систему
        ci_system = self._detect_ci_system(file_path)
        parser = self.parsers.get(ci_system, self.parsers['gitlab'])

        try:
            # Парсинг
            config = parser.parse(file_path)
            all_values = parser.get_all_values_with_context(config)

            # Детекция (выполняем все детекторы по приоритету)
            all_findings = []
            for detector in sorted(self.detectors, key=lambda d: d.get_priority()):
                findings = detector.detect(config, all_values)
                all_findings.extend(findings)

            # Дедупликация находок
            unique_findings = []
            seen_values = set()
            
            for finding in all_findings:
                # Создаём ключ для дедупликации
                key = f"{finding.file}:{finding.value}"
                
                if key not in seen_values:
                    seen_values.add(key)
                    unique_findings.append(finding)
            
            all_findings = unique_findings
            
            # Контекстное обогащение и риск-скоринг
            enhanced_findings = self.contextual_detector.apply_context(all_findings)

            # Валидация формата
            validated_findings = [
                self.validator_manager.validate(f) 
                for f in enhanced_findings
            ]

            duration = (time.time() - start) * 1000

            return ScanResult(
                findings=validated_findings,
                files_scanned=1,
                scan_duration_ms=duration,
                ci_systems_detected=[ci_system],
            )

        except Exception as e:
            duration = (time.time() - start) * 1000
            return ScanResult(
                findings=[],
                files_scanned=1,
                scan_duration_ms=duration,
                ci_systems_detected=[],
                errors=[str(e)],
            )

    def scan_directory(self, dir_path: Path | str) -> ScanResult:
        """
        Сканирует директорию рекурсивно.

        Находит все CI/CD конфигурационные файлы в директории и поддиректориях
        используя glob-паттерны и дополнительный поиск по имени файла.

        Поддерживаемые файлы:
            - GitLab CI: .gitlab-ci.yml, .gitlab/ci/*.yml, .gitlab/ci/*.yaml
            - GitHub Actions: .github/workflows/*.yml, .github/workflows/*.yaml
            - Дополнительные паттерны: gitlab_*.yml, github_*.yml, etc.

        Args:
            dir_path (Path | str): Путь к директории для сканирования

        Returns:
            ScanResult: Агрегированный результат сканирования всех файлов содержащий:
                - findings: Объединённый список всех найденных уязвимостей
                - files_scanned: Количество просканированных файлов
                - scan_duration_ms: Общая длительность сканирования в миллисекундах
                - ci_systems_detected: Список всех обнаруженных CI/CD систем
                - errors: Список ошибок при сканировании отдельных файлов

        Raises:
            Exception: Исключения при сканировании отдельных файлов не прерывают
                      процесс, а добавляются в поле errors результата

        Example:
            >>> engine = ScannerEngine()
            >>> result = engine.scan_directory("./ci-configs/")
            >>> print(f"Scanned {result.files_scanned} files, found {len(result.findings)} secrets")
            Scanned 5 files, found 12 secrets
        """
        dir_path = Path(dir_path)
        all_findings = []
        files_scanned = 0
        ci_systems = set()
        errors = []
        start = time.time()
        
        # Расширенные паттерны для поиска CI/CD файлов
        patterns = [
            '**/.gitlab-ci.yml',
            '**/.gitlab/ci/*.yml',
            '**/.gitlab/ci/*.yaml',
            '**/.github/workflows/*.yml',
            '**/.github/workflows/*.yaml',
            '**/github/workflows/*.yml',
            '**/github/workflows/*.yaml',
            '**/github_workflows.yml',
            '**/github_workflows.yaml',
            '**/github_*.yaml',
            '**/github_*.yml',
            '**/gitlab_*.yaml',
            '**/gitlab_*.yml',
        ]
        
        # Собираем все файлы (используем set для уникальности)
        found_files = set()
        
        for pattern in patterns:
            for file in dir_path.glob(pattern):
                if file.is_file():
                    found_files.add(file)
        
        # Дополнительно: ищем по имени файла (если паттерны не сработали)
        for file in dir_path.rglob('*'):
            if file.is_file():
                file_name = file.name.lower()
                if any([
                    'gitlab-ci' in file_name,
                    file_name.endswith('.gitlab-ci.yml'),
                    '.github/workflows/' in str(file).lower(),
                    'jenkinsfile' in file_name,
                    file_name.endswith('.jenkinsfile'),
                ]):
                    found_files.add(file)
        
        # Сканируем каждый найденный файл
        for file in sorted(found_files):
            try:
                result = self.scan_file(file)
                all_findings.extend(result.findings)
                files_scanned += 1
                ci_systems.update(result.ci_systems_detected)
                errors.extend(result.errors)
            except Exception as e:
                errors.append(f"Error scanning {file}: {str(e)}")
        
        duration = (time.time() - start) * 1000
        
        return ScanResult(
            findings=all_findings,
            files_scanned=files_scanned,
            scan_duration_ms=duration,
            ci_systems_detected=list(ci_systems),
            errors=errors,
        )