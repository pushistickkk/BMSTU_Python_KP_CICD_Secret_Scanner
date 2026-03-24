"""
GitLab CI парсер.
Извлекает структуру конфигурации и все строковые значения с контекстом.
"""

import yaml
from pathlib import Path
from typing import Any, Dict, List, Tuple
from scanner.parsers.base import ParserMixin


class GitLabCIConfig:
    """Структурированное представление .gitlab-ci.yml"""

    def __init__(self, raw_data: dict, file_path: str):
        self.raw = raw_data or {}
        self.file_path = file_path
        self.jobs = self._extract_jobs()
        self.global_vars = self._extract_global_vars()
        self.stages = self._extract_stages()

    def _extract_jobs(self) -> Dict[str, dict]:
        """Извлекает все джобы (исключая служебные ключи)"""
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
        """Извлекает глобальные переменные"""
        vars_section = self.raw.get('variables', {})
        if isinstance(vars_section, dict):
            return {k: str(v) for k, v in vars_section.items()}
        return {}

    def _extract_stages(self) -> List[str]:
        """Извлекает список stages"""
        stages = self.raw.get('stages', [])
        return stages if isinstance(stages, list) else []


class GitLabParser(ParserMixin):
    """
    Парсер для GitLab CI конфигураций.

    Поддерживаемые файлы:
    - .gitlab-ci.yml
    - .gitlab/ci/*.yml
    """

    def get_type(self) -> str:
        return "gitlab"

    def parse(self, file_path: Path | str) -> GitLabCIConfig:
        """
        Парсит YAML файл в структурированный объект.

        Args:
            file_path: Путь к .gitlab-ci.yml

        Returns:
            GitLabCIConfig объект
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

        Args:
            config: Распарсенная конфигурация

        Returns:
            Список кортежей (key_path, value, context_dict)
        """
        results = []

        # 1. Глобальные переменные
        for var_name, var_value in config.global_vars.items():
            if isinstance(var_value, str):
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
                    }
                ))

        # 2. Джобы и их настройки
        for job_name, job_data in config.jobs.items():
            if not isinstance(job_data, dict):
                continue

            # Определяем stage джобы
            job_stage = job_data.get('stage', 'default')

            # Определяем environment (production/staging) - черновой вариант
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

            # Переменные джоб
            job_vars = job_data.get('variables', {})
            if isinstance(job_vars, dict):
                for var_name, var_value in job_vars.items():
                    if isinstance(var_value, str):
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
                            }
                        ))

            # Скрипты
            scripts = job_data.get('script', [])
            if isinstance(scripts, list):
                for i, script_line in enumerate(scripts):
                    if isinstance(script_line, str):
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
                            }
                        ))
            elif isinstance(scripts, str):
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
                        }
                    ))

        return results