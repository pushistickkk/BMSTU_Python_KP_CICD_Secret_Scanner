"""
Scanner Engine — оркестратор пайплайна сканирования.
"""

import time
from pathlib import Path
from typing import List

from scanner.core.models import ScanResult
from scanner.core.risk_scorer import ContextAwareRiskScorer
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
    Основной движок сканера.

    Координирует работу парсеров, детекторов и валидаторов.
    """

    def __init__(self):
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
        Определяет тип CI/CD системы по пути (названию файла).

        Args:
            file_path: Путь к файлу

        Returns:
            str: 'gitlab'( 'github', 'jenkins' )
        """
        path_lower = file_path.name.lower()

        if 'gitlab-ci' in path_lower or path_lower.endswith('.gitlab-ci.yml'):
            return 'gitlab'
        elif '.github' in str(file_path) or 'github' in path_lower:
            return 'github'
        # elif 'jenkinsfile' in path_lower:
        #     return 'jenkins'
        else:
            return 'gitlab'  # По умолчанию


    def scan_file(self, file_path: Path | str) -> ScanResult:
        """
        Сканирует один файл.

        Args:
            file_path: Путь к файлу

        Returns:
            ScanResult с результатами
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

            unique_findings = []
            seen_values = set()
            
            for finding in all_findings:
                # Создаём ключ для дедупликации
                key = f"{finding.file}:{finding.value}"
                
                if key not in seen_values:
                    seen_values.add(key)
                    unique_findings.append(finding)
            
            all_findings = unique_findings
            
            # Контекст
            enhanced_findings = self.contextual_detector.apply_context(all_findings)

            # Валидация
            validated_findings = [
                self.validator_manager.validate(f) 
                for f in enhanced_findings
            ]

            duration = (time.time() - start) * 1000

            return ScanResult(
                findings=validated_findings, # уже провалидированные файндинги с контекстом
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
        Находит все CI/CD конфигурационные файлы.
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
            # '**/Jenkinsfile',
            # '**/Jenkinsfile.*',
            # '**/*.jenkinsfile',
            # '**/*.jenkins',
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