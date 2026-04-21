"""
GitLab CI парсер.

Этот модуль предоставляет класс GitLabParser для парсинга конфигурационных
файлов GitLab CI (.gitlab-ci.yml).

Поддерживаемые секции:
- variables: Глобальные и job-level переменные
- stages: Определение этапов пайплайна
- jobs: Определение джоб и их настроек
- script: Команды для выполнения
- environment: Окружение деплоя

Пример использования:
    >>> from scanner.parsers.gitlab import GitLabParser
    >>> parser = GitLabParser()
    >>> config = parser.parse('.gitlab-ci.yml')
    >>> values = parser.get_all_values_with_context(config)
    >>> print(f"Found {len(values)} values to scan")
    Found 12 values to scan
"""

import yaml
from pathlib import Path
from typing import Any, Dict, List, Tuple
from scanner.parsers.base import ParserMixin


class GitLabCIConfig:
    """
    Структурированное представление конфигурации GitLab CI.

    Этот класс хранит распарсенные данные .gitlab-ci.yml и предоставляет
    методы для извлечения компонентов конфигурации.

    Attributes:
        raw (dict): Исходные данные YAML после парсинга
        file_path (str): Путь к файлу конфигурации
        jobs (dict): Словарь джоб (исключая служебные ключи)
        global_vars (dict): Глобальные переменные из секции 'variables'
        stages (list): Список этапов из секции 'stages'

    Example:
        >>> config = GitLabCIConfig({'stages': ['build', 'deploy']}, 'ci.yml')
        >>> print(config.stages)
        ['build', 'deploy']
        >>> print(config.jobs)
        {}
    """

    def __init__(self, raw_data: dict, file_path: str):
        """
        Инициализирует конфигурацию GitLab CI.

        Args:
            raw_ dict): Исходные данные после yaml.safe_load()
            file_path (str): Путь к файлу конфигурации
        """
        self.raw = raw_data or {}
        self.file_path = file_path
        self.jobs = self._extract_jobs()
        self.global_vars = self._extract_global_vars()
        self.stages = self._extract_stages()

    def _extract_jobs(self) -> Dict[str, dict]:
        """
        Извлекает джобы из конфигурации (исключая служебные ключи).

        Служебные ключи которые не являются джобами:
        - stages, variables, include, default, workflow
        - image, services, before_script, after_script, cache

        Returns:
            Dict[str, dict]: Словарь джоб где ключ — имя джобы
        """
        reserved_keys = {
            'stages', 'variables', 'include', 'default',
            'workflow', 'image', 'services', 'before_script',
            'after_script', 'cache'
        }
        return {
            k: v for k, v in self.raw.items()
            if k not in reserved_keys and isinstance(v, dict)
        }

    def _extract_global_vars(self) -> Dict[str, str]:
        """
        Извлекает глобальные переменные из секции 'variables'.

        Returns:
            Dict[str, str]: Словарь переменных {name: value}
        """
        vars_section = self.raw.get('variables', {})
        if isinstance(vars_section, dict):
            return {k: str(v) for k, v in vars_section.items()}
        return {}

    def _extract_stages(self) -> List[str]:
        """
        Извлекает список этапов из секции 'stages'.

        Returns:
            List[str]: Список названий этапов
        """
        stages = self.raw.get('stages', [])
        return stages if isinstance(stages, list) else []


class GitLabParser(ParserMixin):
    """
    Парсер для конфигурационных файлов GitLab CI.

    Поддерживаемые файлы:
    - .gitlab-ci.yml
    - .gitlab/ci/*.yml

    Извлекаемые данные:
    - Глобальные variables
    - Джобы и их переменные
    - Скрипты (script)
    - Окружения деплоя (environment)

    Example:
        >>> parser = GitLabParser()
        >>> config = parser.parse('.gitlab-ci.yml')
        >>> values = parser.get_all_values_with_context(config)
        >>> print(f"Extracted {len(values)} values")
        Extracted 12 values
    """

    def get_type(self) -> str:
        """
        Возвращает тип CI/CD системы.

        Returns:
            str: 'gitlab'
        """
        return "gitlab"

    def parse(self, file_path: Path | str) -> GitLabCIConfig:
        """
        Парсит YAML файл в структурированный объект.

        Args:
            file_path (Path | str): Путь к файлу .gitlab-ci.yml

        Returns:
            GitLabCIConfig: Объект с распарсенной конфигурацией

        Raises:
            FileNotFoundError: Если файл не существует
            yaml.YAMLError: Если файл содержит невалидный YAML
            IOError: Если файл не может быть прочитан

        Example:
            >>> parser = GitLabParser()
            >>> config = parser.parse('.gitlab-ci.yml')
            >>> print(config.stages)
            ['build', 'test', 'deploy']
        """
        file_path = Path(file_path)

        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        return GitLabCIConfig(data, str(file_path))

    def get_all_values_with_context(
        self,
        config: GitLabCIConfig
    ) -> List[Tuple[str, str, Dict[str, Any]]]:
        """
        Извлекает все строковые значения с контекстом пайплайна.

        Проходит по всем секциям конфигурации:
        1. Глобальные variables
        2. Джобы и их переменные
        3. Скрипты (script)
        4. Прочие строковые поля джоб

        Args:
            config (GitLabCIConfig): Распарсенная конфигурация

        Returns:
            List[Tuple[str, str, Dict[str, Any]]]: Список кортежей:
                - key_path (str): Путь к значению
                - value (str): Строковое значение
                - context_dict (dict): Метаданные контекста:
                    - ci_system: 'gitlab'
                    - section: 'global_variables' | 'job_variables' | 'script' | 'job_config'
                    - variable_name: Имя переменной
                    - stage: Этап пайплайна
                    - job_name: Имя джобы
                    - environment: Окружение
                    - is_production: Флаг production
                    - line: Номер строки в файле

        Example:
            >>> parser = GitLabParser()
            >>> config = parser.parse('.gitlab-ci.yml')
            >>> values = parser.get_all_values_with_context(config)
            >>> for path, value, ctx in values:
            ...     if 'AWS' in value:
            ...         print(f"{path}: {ctx['stage']}")
            variables.AWS_KEY: deploy
        """
        results = []

        # 1. Глобальные переменные
        for var_name, var_value in config.global_vars.items():
            if isinstance(var_value, str):
                line_num = self._find_line_number(config.file_path, var_name, var_value)
                results.append((
                    f"variables.{var_name}",
                    var_value,
                    {
                        "ci_system": "gitlab",
                        "section": "global_variables",
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

            # Определяем stage джобы
            job_stage = job_data.get('stage', 'default')

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

            # Переменные джоба
            job_vars = job_data.get('variables', {})
            if isinstance(job_vars, dict):
                for var_name, var_value in job_vars.items():
                    if isinstance(var_value, str):
                        line_num = self._find_line_number(config.file_path, var_name, var_value)
                        results.append((
                            f"jobs.{job_name}.variables.{var_name}",
                            var_value,
                            {
                                "ci_system": "gitlab",
                                "section": "job_variables",
                                "variable_name": var_name,
                                "stage": str(job_stage),
                                "job_name": job_name,
                                "environment": environment,
                                "is_production": is_production,
                                "line": line_num,
                            }
                        ))

            # Скрипты
            scripts = job_data.get('script', [])
            if isinstance(scripts, list):
                for i, script_line in enumerate(scripts):
                    if isinstance(script_line, str):
                        line_num = self._find_line_number(config.file_path, '', script_line[:30])
                        results.append((
                            f"jobs.{job_name}.script[{i}]",
                            script_line,
                            {
                                "ci_system": "gitlab",
                                "section": "script",
                                "stage": str(job_stage),
                                "job_name": job_name,
                                "environment": environment,
                                "is_production": is_production,
                                "script_content": script_line,
                                "line": line_num,
                            }
                        ))
            elif isinstance(scripts, str):
                line_num = self._find_line_number(config.file_path, '', scripts[:30])
                results.append((
                    f"jobs.{job_name}.script",
                    scripts,
                    {
                        "ci_system": "gitlab",
                        "section": "script",
                        "stage": str(job_stage),
                        "job_name": job_name,
                        "environment": environment,
                        "is_production": is_production,
                        "script_content": scripts,
                        "line": line_num,
                    }
                ))

            # Прочие строковые поля
            for key, value in job_data.items():
                if key in {'variables', 'script', 'stage', 'environment'}:
                    continue
                if isinstance(value, str):
                    results.append((
                        f"jobs.{job_name}.{key}",
                        value,
                        {
                            "ci_system": "gitlab",
                            "section": "job_config",
                            "key": key,
                            "stage": str(job_stage),
                            "job_name": job_name,
                            "environment": environment,
                            "is_production": is_production,
                            "line": 0,
                        }
                    ))

        return results

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
            >>> parser = GitLabParser()
            >>> line = parser._find_line_number('.gitlab-ci.yml', 'AWS_KEY', 'AKIAIOSFOD')
            >>> print(line)
            12
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if search_key in line and search_value[:10] in line:
                        return line_num
        except Exception:
            pass  # Игнорируем ошибки чтения файла
        return 0