"""
GitHub Actions парсер.
"""

import yaml
from pathlib import Path
from typing import Any, Dict, List, Tuple
from scanner.parsers.base import ParserMixin


class GitHubActionsConfig:
    """Структурированное представление .github/workflows/*.yml"""
    
    def __init__(self, raw_data: dict, file_path: str):
        self.raw = raw_data or {}
        self.file_path = file_path
        self.jobs = self._extract_jobs()
        self.global_env = self._extract_global_env()
        self.workflow_name = self._extract_name()
    
    def _extract_jobs(self) -> Dict[str, dict]:
        """Извлекает все джобы из workflows"""
        jobs_section = self.raw.get('jobs', {})
        return jobs_section if isinstance(jobs_section, dict) else {}
    
    def _extract_global_env(self) -> Dict[str, str]:
        """Извлекает глобальные переменные окружения"""
        env_section = self.raw.get('env', {})
        if isinstance(env_section, dict):
            return {k: str(v) for k, v in env_section.items()}
        return {}
    
    def _extract_name(self) -> str:
        """Извлекает имя workflow"""
        return self.raw.get('name', '')


class GitHubParser(ParserMixin):
    """
    Парсер для GitHub Actions workflows.
    
    Поддерживаемые файлы:
    - .github/workflows/*.yml
    - .github/workflows/*.yaml
    """
    
    def get_type(self) -> str:
        return "github"
    
    def parse(self, file_path: Path | str) -> GitHubActionsConfig:
        """
        Парсит YAML файл в структурированный объект.
        Args:
            file_path: Путь к workflow файлу
        Returns:
            GitHubActionsConfig объект
        """
        file_path = Path(file_path)
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        return GitHubActionsConfig(data, str(file_path))
    
    def get_all_values_with_context(self, config: GitHubActionsConfig) -> List[Tuple[str, str, Dict[str, Any]]]:
        """
        Извлекает все строковые значения с контекстом workflow.
        Args:
            config: Распарсенная конфигурация
        Returns:
            Список кортежей (key_path, value, context_dict)
        """
        results = []
        
        # 1. Глобальные env
        for var_name, var_value in config.global_env.items():
            if isinstance(var_value, str):
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
                    }
                ))
        
        # 2. Jobs
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
            
            # Job-level env
            job_env = job_data.get('env', {})
            if isinstance(job_env, dict):
                for var_name, var_value in job_env.items():
                    if isinstance(var_value, str):
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
                            }
                        ))
            
            # Steps
            steps = job_data.get('steps', [])
            if isinstance(steps, list):
                for i, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue
                    
                    # Step env
                    step_env = step.get('env', {})
                    if isinstance(step_env, dict):
                        for var_name, var_value in step_env.items():
                            if isinstance(var_value, str):
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
                                    }
                                ))
                    
                    # Step run
                    run_script = step.get('run', '')
                    if isinstance(run_script, str):
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
                            }
                        ))
                    
                    # Step with arguments
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
                                    }
                                ))
        
        return results
    
    def _infer_stage(self, job_name: str, job: dict,) -> str:
        """
        Определяет stage по имени джобы или содержимому.
        Args:
            job_name: Имя джобы
            job_data: Данные джобы
        Returns:
            str: 'build', 'test', 'deploy', 'lint', 'unknown'
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
        """Ищет номер строки с ключом и значением в файле."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if search_key in line and search_value[:10] in line:
                        return line_num
        except:
            pass
        return 0
    
    def get_all_values_with_context(
        self, 
        config: GitHubActionsConfig
    ) -> List[Tuple[str, str, Dict[str, Any]]]:
        """Извлекает все строковые значения с контекстом workflow."""
        results = []
        
        # 1. Глобальные env
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
                        "line": line_num,  # Добавляем номер строки
                    }
                ))
        
        # 2. Jobs
        for job_name, job_data in config.jobs.items():
            if not isinstance(job_data, dict):
                continue
            
            stage = self._infer_stage(job_name, job_data)
            
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
            
            # Job-level env
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
                                "line": line_num,  # Добавляем номер строки
                            }
                        ))
            
            # Steps
            steps = job_data.get('steps', [])
            if isinstance(steps, list):
                for i, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue
                    
                    # Step env
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
                                        "line": line_num,  # ✅ Добавляем номер строки
                                    }
                                ))
                    
                    # Step run (script)
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
                                "line": line_num,  # Добавляем номер строки
                            }
                        ))
        
        return results