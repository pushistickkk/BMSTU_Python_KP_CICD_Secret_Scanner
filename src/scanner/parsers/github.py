"""
GitHub Actions парсер.

Этот модуль предоставляет класс GitHubParser для парсинга конфигурационных
файлов GitHub Actions (.github/workflows/*.yml).

Поддерживаемые секции:
- env: Глобальные и job-level переменные окружения
- jobs: Определение джоб и их настроек
- steps: Шаги джобы (run, with, env)
- environment: Окружение деплоя

Пример использования:
    >>> from scanner.parsers.github import GitHubParser
    >>> parser = GitHubParser()
    >>> config = parser.parse('.github/workflows/deploy.yml')
    >>> values = parser.get_all_values_with_context(config)
    >>> print(f"Found {len(values)} values to scan")
    Found 15 values to scan
"""

import yaml
from pathlib import Path
from typing import Any, Dict, List, Tuple
from scanner.parsers.base import ParserMixin


class GitHubActionsConfig:
    """
    Структурированное представление конфигурации GitHub Actions.

    Этот класс хранит распарсенные данные workflow файла и предоставляет
    методы для извлечения компонентов конфигурации.

    Attributes:
        raw (dict): Исходные данные YAML после парсинга
        file_path (str): Путь к файлу конфигурации
        jobs (dict): Словарь джоб из секции 'jobs'
        global_env (dict): Глобальные переменные окружения из секции 'env'
        workflow_name (str): Имя workflow из поля 'name'

    Example:
        >>> config = GitHubActionsConfig({'name': 'Deploy'}, 'deploy.yml')
        >>> print(config.workflow_name)
        Deploy
        >>> print(config.jobs)
        {}
    """

    def __init__(self, raw_data: dict, file_path: str):
        """
        Инициализирует конфигурацию GitHub Actions.

        Args:
            raw_ dict): Исходные данные после yaml.safe_load()
            file_path (str): Путь к файлу конфигурации
        """
        self.raw = raw_data or {}
        self.file_path = file_path
        self.jobs = self._extract_jobs()
        self.global_env = self._extract_global_env()
        self.workflow_name = self._extract_name()

    def _extract_jobs(self) -> Dict[str, dict]:
        """
        Извлекает секцию джоб из конфигурации.

        Returns:
            Dict[str, dict]: Словарь джоб где ключ — имя джобы,
                           значение — настройки джобы
        """
        jobs_section = self.raw.get('jobs', {})
        return jobs_section if isinstance(jobs_section, dict) else {}

    def _extract_global_env(self) -> Dict[str, str]:
        """
        Извлекает глобальные переменные окружения.

        Returns:
            Dict[str, str]: Словарь переменных {name: value}
        """
        env_section = self.raw.get('env', {})
        if isinstance(env_section, dict):
            return {k: str(v) for k, v in env_section.items()}
        return {}

    def _extract_name(self) -> str:
        """
        Извлекает имя workflow.

        Returns:
            str: Имя workflow или пустая строка если не указано
        """
        return self.raw.get('name', '')


class GitHubParser(ParserMixin):
    """
    Парсер для конфигурационных файлов GitHub Actions.

    Поддерживаемые файлы:
    - .github/workflows/*.yml
    - .github/workflows/*.yaml

    Извлекаемые данные:
    - Глобальные env переменные
    - Джобы и их настройки
    - Переменные на уровне джобы и шага
    - Скрипты (run) и аргументы действий (with)
    - Окружения деплоя (environment)

    Example:
        >>> parser = GitHubParser()
        >>> config = parser.parse('.github/workflows/deploy.yml')
        >>> values = parser.get_all_values_with_context(config)
        >>> print(f"Extracted {len(values)} values")
        Extracted 15 values
    """

    def get_type(self) -> str:
        """
        Возвращает тип CI/CD системы.

        Returns:
            str: 'github'
        """
        return "github"

    def parse(self, file_path: Path | str) -> GitHubActionsConfig:
        """
        Парсит YAML файл workflow в структурированный объект.

        Args:
            file_path (Path | str): Путь к файлу .github/workflows/*.yml

        Returns:
            GitHubActionsConfig: Объект с распарсенной конфигурацией

        Raises:
            FileNotFoundError: Если файл не существует
            yaml.YAMLError: Если файл содержит невалидный YAML
            IOError: Если файл не может быть прочитан

        Example:
            >>> parser = GitHubParser()
            >>> config = parser.parse('.github/workflows/deploy.yml')
            >>> print(config.workflow_name)
            Deploy Pipeline
        """
        file_path = Path(file_path)

        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        return GitHubActionsConfig(data, str(file_path))

    def get_all_values_with_context(
        self,
        config: GitHubActionsConfig
    ) -> List[Tuple[str, str, Dict[str, Any]]]:
        """
        Извлекает все строковые значения с контекстом workflow.

        Проходит по всем секциям конфигурации:
        1. Глобальные env переменные
        2. Джобы и их переменные
        3. Шаги джобы (env, run, with)

        Args:
            config (GitHubActionsConfig): Распарсенная конфигурация

        Returns:
            List[Tuple[str, str, Dict[str, Any]]]: Список кортежей:
                - key_path (str): Путь к значению (env.VAR, jobs.name.env.VAR)
                - value (str): Строковое значение
                - context_dict (dict): Метаданные контекста:
                    - ci_system: 'github'
                    - section: 'global_env' | 'job_env' | 'step_env' | 'step_run' | 'step_with'
                    - variable_name: Имя переменной
                    - stage: Этап пайплайна (build/test/deploy/lint)
                    - job_name: Имя джобы
                    - environment: Окружение
                    - is_production: Флаг production окружения
                    - line: Номер строки в файле

        Example:
            >>> parser = GitHubParser()
            >>> config = parser.parse('.github/workflows/deploy.yml')
            >>> values = parser.get_all_values_with_context(config)
            >>> for path, value, ctx in values:
            ...     if 'AWS' in value:
            ...         print(f"{path}: {ctx['stage']}/{ctx['environment']}")
            env.AWS_KEY: deploy/production
        """
        results = []

        # 1. Глобальные env переменные
        for var_name, var_value in config.global_env.items():
            if isinstance(var_value, str):
                line_num = self._find_line_number(config.file_path, var_name, var_value)
                results.append((
                    f"env.{var_name}",
                    var_value,
                    {
                        "ci_system": "github",
                        "section": "global_env",
                        "variable_name": var_name,
                        "stage": "",
                        "job_name": "",
                        "environment": "",
                        "is_production": False,
                        "line": line_num,
                    }
                ))

        # 2. Джобы и их настройки
        for job_name, job_data in config.jobs.items():
            if not isinstance(job_data, dict):
                continue

            # Определяем stage по имени джобы
            stage = self._infer_stage(job_name, job_data)

            # Определяем environment
            env_config = job_data.get('environment', {})
            if isinstance(env_config, str):
                environment = env_config
            elif isinstance(env_config, dict):
                environment = env_config.get('name', '')
            else:
                environment = ''

            is_production = any(
                kw in environment.lower()
                for kw in ['prod', 'production', 'main', 'master']
            )

            # Job-level env переменные
            job_env = job_data.get('env', {})
            if isinstance(job_env, dict):
                for var_name, var_value in job_env.items():
                    if isinstance(var_value, str):
                        line_num = self._find_line_number(config.file_path, var_name, var_value)
                        results.append((
                            f"jobs.{job_name}.env.{var_name}",
                            var_value,
                            {
                                "ci_system": "github",
                                "section": "job_env",
                                "variable_name": var_name,
                                "stage": stage,
                                "job_name": job_name,
                                "environment": environment,
                                "is_production": is_production,
                                "line": line_num,
                            }
                        ))

            # Шаги джобы
            steps = job_data.get('steps', [])
            if isinstance(steps, list):
                for i, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue

                    # Step env переменные
                    step_env = step.get('env', {})
                    if isinstance(step_env, dict):
                        for var_name, var_value in step_env.items():
                            if isinstance(var_value, str):
                                line_num = self._find_line_number(config.file_path, var_name, var_value)
                                results.append((
                                    f"jobs.{job_name}.steps[{i}].env.{var_name}",
                                    var_value,
                                    {
                                        "ci_system": "github",
                                        "section": "step_env",
                                        "variable_name": var_name,
                                        "stage": stage,
                                        "job_name": job_name,
                                        "environment": environment,
                                        "is_production": is_production,
                                        "line": line_num,
                                    }
                                ))

                    # Step run (скрипт)
                    run_script = step.get('run', '')
                    if isinstance(run_script, str):
                        line_num = self._find_line_number(config.file_path, '', run_script[:30])
                        results.append((
                            f"jobs.{job_name}.steps[{i}].run",
                            run_script,
                            {
                                "ci_system": "github",
                                "section": "step_run",
                                "stage": stage,
                                "job_name": job_name,
                                "environment": environment,
                                "is_production": is_production,
                                "script_content": run_script,
                                "line": line_num,
                            }
                        ))

                    # Step with (аргументы действий)
                    step_with = step.get('with', {})
                    if isinstance(step_with, dict):
                        for key, value in step_with.items():
                            if isinstance(value, str):
                                results.append((
                                    f"jobs.{job_name}.steps[{i}].with.{key}",
                                    value,
                                    {
                                        "ci_system": "github",
                                        "section": "step_with",
                                        "key": key,
                                        "stage": stage,
                                        "job_name": job_name,
                                        "environment": environment,
                                        "is_production": is_production,
                                        "line": 0,  # Для with не ищем строку
                                    }
                                ))

        return results

    def _infer_stage(self, job_name: str, job: dict,) -> str:
        """
        Определяет этап пайплайна по имени джобы или её содержимому.

        Использует эвристики на основе ключевых слов в имени джобы:
        - deploy/release/publish → 'deploy'
        - test/spec/check → 'test'
        - build/compile/make → 'build'
        - lint/format → 'lint'
        - иначе → 'unknown'

        Args:
            job_name (str): Имя джобы из конфигурации
            job_ dict): Настройки джобы (для будущего расширения)

        Returns:
            str: Этап пайплайна ('build', 'test', 'deploy', 'lint', 'unknown')

        Example:
            >>> parser = GitHubParser()
            >>> parser._infer_stage('deploy-production', {})
            'deploy'
            >>> parser._infer_stage('run-tests', {})
            'test'
            >>> parser._infer_stage('custom-job', {})
            'unknown'
        """
        job_name_lower = job_name.lower()

        if any(k in job_name_lower for k in ['deploy', 'release', 'publish']):
            return 'deploy'
        elif any(k in job_name_lower for k in ['test', 'spec', 'check']):
            return 'test'
        elif any(k in job_name_lower for k in ['build', 'compile', 'make']):
            return 'build'
        elif any(k in job_name_lower for k in ['lint', 'format']):
            return 'lint'
        else:
            return 'unknown'

    def _find_line_number(self, file_path: str, search_key: str, search_value: str) -> int:
        """
        Ищет номер строки с ключом и значением в файле.

        Использует простой поиск подстроки для определения номера строки.
        Возвращает 0 если не найдено.

        Примечание: Это эвристический метод который может быть неточным
        для сложных случаев (мультилайн значения, комментарии и т.д.)

        Args:
            file_path (str): Путь к файлу для поиска
            search_key (str): Ключ для поиска (имя переменной)
            search_value (str): Значение для поиска (первые 10 символов)

        Returns:
            int: Номер строки (1-based) или 0 если не найдено

        Example:
            >>> parser = GitHubParser()
            >>> line = parser._find_line_number('deploy.yml', 'AWS_KEY', 'AKIAIOSFOD')
            >>> print(line)
            15
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if search_key in line and search_value[:10] in line:
                        return line_num
        except Exception:
            pass  # Игнорируем ошибки чтения файла
        return 0