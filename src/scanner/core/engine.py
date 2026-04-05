"""
Scanner Engine — оркестратор пайплайна сканирования.
"""

import time
from pathlib import Path
from typing import List
from scanner.core.models import ScanResult
from scanner.parsers.gitlab import GitLabParser
from scanner.detectors.regex import RegexDetector

from scanner.parsers.github import GitHubParser
from scanner.detectors.contextual import ContextualDetector
from scanner.core.risk_scorer import ContextAwareRiskScorer


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
        ]
        self.contextual_detector = ContextualDetector()
        self.scorer = ContextAwareRiskScorer()

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
            
            enhanced_findings = self.contextual_detector.apply_context(all_findings)

            duration = (time.time() - start) * 1000

            return ScanResult(
                findings=enhanced_findings,
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

        Args:
            dir_path: Путь к директории

        Returns:
            ScanResult с результатами
        """
        dir_path = Path(dir_path)
        all_findings = []
        files_scanned = 0
        ci_systems = set()
        errors = []
        start = time.time()

        # Паттерны для поиска
        patterns = [
            '**/.gitlab-ci.yml',
            '**/.gitlab/ci/*.yml',
            # '**/.github/workflows/*.yml',
            # '**/.github/workflows/*.yaml',
            # '**/Jenkinsfile',
            # '**/*.jenkinsfile',
        ]

        for pattern in patterns:
            for file in dir_path.glob(pattern):
                result = self.scan_file(file)
                all_findings.extend(result.findings)
                files_scanned += 1
                ci_systems.update(result.ci_systems_detected)
                errors.extend(result.errors)

        duration = (time.time() - start) * 1000

        return ScanResult(
            findings=all_findings,
            files_scanned=files_scanned,
            scan_duration_ms=duration,
            ci_systems_detected=list(ci_systems),
            errors=errors,
        )