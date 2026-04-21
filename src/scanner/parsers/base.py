"""
Базовый класс для всех парсеров.

Этот модуль предоставляет класс-миксин ParserMixin который реализует
абстрактный интерфейс BaseParser. Наследование от этого класса
гарантирует что все парсеры имеют одинаковый интерфейс.
"""

from scanner.core.interfaces import BaseParser


class ParserMixin(BaseParser):
    """
    Базовая реализация общих методов парсеров.

    Этот класс предоставляет общую структуру для всех парсеров
    конфигурационных файлов CI/CD систем.

    Планируемая функциональность:
    - Загрузка YAML через pyyaml
    - Поиск секций variables:, script:, image:
    - Извлечение значений с контекстом: {stage: "deploy", job: "prod", section: "variables"}

    Наследники должны переопределить:
    - get_type(): Возвращает идентификатор типа CI/CD системы
    - parse(): Парсит файл в структурированный объект
    - get_all_values_with_context(): Извлекает значения с метаданными

    Example:
        >>> class GitLabParser(ParserMixin):
        ...     def get_type(self) -> str:
        ...         return 'gitlab'
        ...     def parse(self, file_path):
        ...         pass
        ...     def get_all_values_with_context(self, config):
        ...         pass
    """

    def get_type(self) -> str:
        """
        Возвращает тип CI/CD системы.

        Должен быть переопределён в наследниках.

        Returns:
            str: Идентификатор типа системы ('gitlab', 'github', 'jenkins')

        Raises:
            NotImplementedError: Если метод не переопределён

        Example:
            >>> parser = GitLabParser()
            >>> parser.get_type()
            'gitlab'
        """
        raise NotImplementedError

    def parse(self, file_path: str) -> any:
        """
        Парсит файл конфигурации в структурированный объект.

        Должен быть переопределён в наследниках.

        Читает файл с диска, анализирует его структуру и возвращает
        объектное представление конфигурации.

        Args:
            file_path (str): Путь к файлу конфигурации

        Returns:
            any: Структурированный объект конфигурации
                Тип зависит от реализации парсера

        Raises:
            NotImplementedError: Если метод не переопределён
            FileNotFoundError: Если файл не существует
            yaml.YAMLError: Если файл содержит невалидный YAML

        Example:
            >>> parser = GitLabParser()
            >>> config = parser.parse('.gitlab-ci.yml')
            >>> print(type(config))
            <class 'scanner.parsers.gitlab.GitLabCIConfig'>
        """
        raise NotImplementedError

    def get_all_values_with_context(
        self,
        config: any
    ) -> list[tuple[str, str, dict[str, any]]]:
        """
        Извлекает все строковые значения с контекстом из конфигурации.

        Должен быть переопределён в наследниках.

        Проходит по всем полям конфигурации и извлекает строковые значения
        вместе с метаданными о их расположении в пайплайне.

        Args:
            config (any): Распарсенная конфигурация (результат метода parse)

        Returns:
            list[tuple[str, str, dict[str, any]]]: Список кортежей содержащих:
                - key_path (str): Путь к значению в конфигурации
                - value (str): Строковое значение
                - context_dict (dict): Словарь с метаданными контекста:
                    - ci_system (str): Тип CI/CD системы
                    - stage (str): Этап пайплайна
                    - job_name (str): Имя джобы
                    - environment (str): Окружение
                    - is_production (bool): Флаг production
                    - section (str): Секция конфига
                    - variable_name (str): Имя переменной
                    - line (int): Номер строки в файле

        Raises:
            NotImplementedError: Если метод не переопределён

        Example:
            >>> parser = GitLabParser()
            >>> config = parser.parse('.gitlab-ci.yml')
            >>> values = parser.get_all_values_with_context(config)
            >>> for key_path, value, context in values:
            ...     print(f"{key_path}: {value} (stage={context['stage']})")
            variables.AWS_KEY: AKIA***MPLE (stage=deploy)
        """
        raise NotImplementedError