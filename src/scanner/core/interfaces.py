"""
Базовые интерфейсы для модулей сканера.

Этот модуль определяет абстрактные базовые классы (ABC) для всех основных
компонентов сканера. Использование интерфейсов обеспечивает:
    - Единый контракт для всех реализаций
    - Возможность легкой замены компонентов
    - Типобезопасность и проверяемость кода
    - Следование принципу Dependency Inversion (DIP из SOLID)

Классы:
    BaseParser: Базовый класс для парсеров CI/CD конфигураций
    BaseDetector: Базовый класс для детекторов секретов
    BaseValidator: Базовый класс для валидаторов формата
    BaseReporter: Базовый класс для репортёров (вывод результатов)

Пример использования:
    >>> from scanner.parsers.gitlab import GitLabParser
    >>> parser = GitLabParser()  # Реализует BaseParser
    >>> print(parser.get_type())
    'gitlab'
"""

from abc import ABC, abstractmethod
from typing import List, Any, Dict
from pathlib import Path


class BaseParser(ABC):
    """
    Базовый класс для парсеров CI/CD конфигураций.

    Определяет контракт для всех парсеров конфигурационных файлов CI/CD систем.
    Каждый парсер должен уметь:
    - Определить тип CI/CD системы (get_type)
    - Распарсить файл в структурированный объект (parse)
    - Извлечь все строковые значения с контекстом (get_all_values_with_context)

    Наследование от этого класса гарантирует что все парсеры имеют одинаковый
    интерфейс и могут использоваться взаимозаменяемо в ScannerEngine.

    Attributes:
        None: Этот класс не имеет атрибутов, только методы

    Example:
        >>> class GitLabParser(BaseParser):
        ...     def get_type(self) -> str:
        ...         return 'gitlab'
        ...     def parse(self, file_path):
        ...         pass
        ...     def get_all_values_with_context(self, config):
        ...         pass
    """

    @abstractmethod
    def get_type(self) -> str:
        """
        Возвращает тип CI/CD системы.

        Этот метод используется ScannerEngine для определения типа парсера
        и для логгирования/отчётности.

        Returns:
            str: Идентификатор типа CI/CD системы.
                 Возможные значения: 'gitlab', 'github', 'jenkins'

        Example:
            >>> parser = GitLabParser()
            >>> parser.get_type()
            'gitlab'
        """
        pass

    @abstractmethod
    def parse(self, file_path: Path | str) -> Any:
        """
        Парсит файл конфигурации в структурированный объект.

        Читает файл с диска, анализирует его структуру и возвращает
        объектное представление конфигурации CI/CD пайплайна.

        Args:
            file_path (Path | str): Путь к файлу конфигурации.
                                   Например: '.gitlab-ci.yml'

        Returns:
            Any: Структурированный объект конфигурации.
                 Тип зависит от реализации парсера:
                 - GitLabParser: GitLabCIConfig
                 - GitHubParser: GitHubActionsConfig
                 - JenkinsParser: JenkinsConfig

        Raises:
            FileNotFoundError: Если файл не существует
            yaml.YAMLError: Если файл содержит невалидный YAML
            IOError: Если файл не может быть прочитан

        Example:
            >>> parser = GitLabParser()
            >>> config = parser.parse('.gitlab-ci.yml')
            >>> print(type(config))
            <class 'scanner.parsers.gitlab.GitLabCIConfig'>
        """
        pass

    @abstractmethod
    def get_all_values_with_context(
            self,
            config: Any
    ) -> List[tuple[str, str, Dict[str, Any]]]:
        """
        Извлекает все строковые значения с контекстом из конфигурации.

        Проходит по всем полям конфигурации и извлекает строковые значения
        вместе с метаданными о их расположении в пайплайне.

        Args:
            config (Any): Распарсенная конфигурация (результат метода parse).
                         Тип зависит от реализации парсера.

        Returns:
            List[tuple[str, str, Dict[str, Any]]]: Список кортежей содержащих:
                - key_path (str): Путь к значению в конфигурации
                                 Например: 'variables.AWS_KEY', 'jobs.build.script[0]'
                - value (str): Строковое значение
                - context_dict (dict): Словарь с метаданными контекста:
                    - ci_system (str): Тип CI/CD системы
                    - stage (str): Этап пайплайна (build/test/deploy)
                    - job_name (str): Имя джобы
                    - environment (str): Окружение (production/staging/dev)
                    - is_production (bool): Флаг production окружения
                    - section (str): Секция конфига (variables/script/env)
                    - variable_name (str): Имя переменной (если применимо)
                    - line (int): Номер строки в файле

        Example:
            >>> parser = GitLabParser()
            >>> config = parser.parse('.gitlab-ci.yml')
            >>> values = parser.get_all_values_with_context(config)
            >>> for key_path, value, context in values:
            ...     print(f"{key_path}: {value} (stage={context['stage']})")
            variables.AWS_KEY: AKIA***MPLE (stage=deploy)
        """
        pass


class BaseDetector(ABC):
    """
    Базовый класс для детекторов секретов.

    Определяет контракт для всех детекторов которые ищут секреты
    в конфигурационных файлах CI/CD.

    Архитектура детекции:
    - Детекторы выполняются по приоритету (get_priority)
    - RegexDetector (priority=1) → ищет известные паттерны
    - EntropyDetector (priority=3) → ищет неизвестные форматы
    - ContextualDetector (priority=2) → обогащает находки контекстом

    Каждый детектор должен уметь:
    - Определить приоритет выполнения (get_priority)
    - Найти секреты в предоставленных данных (detect)

    Attributes:
        None: Этот класс не имеет атрибутов, только методы

    Example:
        >>> class RegexDetector(BaseDetector):
        ...     def get_priority(self) -> int:
        ...         return 1
        ...     def detect(self, config, all_values):
        ...         findings = []
        ...         # Логика детекции
        ...         return findings
    """

    @abstractmethod
    def get_priority(self) -> int:
        """
        Возвращает приоритет выполнения детектора.

        Детекторы выполняются в порядке возрастания приоритета
        (меньшее число = выше приоритет).

        Шкала приоритетов:
            1: Высокий приоритет (RegexDetector)
            2: Средний приоритет (ContextualDetector)
            3: Низкий приоритет (EntropyDetector)

        Returns:
            int: Число от 1 до 5 где 1 = самый высокий приоритет.

        Example:
            >>> detector = RegexDetector()
            >>> detector.get_priority()
            1
        """
        pass

    @abstractmethod
    def detect(
            self,
            config: Any,
            all_values: List[tuple[str, str, Dict[str, Any]]]
    ) -> List[Any]:
        """
        Ищет секреты в предоставленных значениях.

        Основной метод детектора который анализирует извлечённые из
        конфигурации значения и возвращает список найденных уязвимостей.

        Args:
            config (Any): Распарсенная конфигурация CI/CD.
                         Используется для получения метаданных (file_path и т.д.)
            all_values (List[tuple[str, str, Dict[str, Any]]]): Список кортежей
                         содержащих извлечённые значения:
                         - key_path (str): Путь к значению
                         - value (str): Строковое значение
                         - context (dict): Контекст (stage, environment, etc.)

        Returns:
            List[Finding]: Список объектов Finding содержащих информацию
                          о найденных уязвимостях. Пустой список если
                          секреты не найдены.

        Example:
            >>> detector = RegexDetector()
            >>> findings = detector.detect(config, values)
            >>> for finding in findings:
            ...     print(f"{finding.secret_type}: {finding.redacted_value}")
            AWS_ACCESS_KEY_ID: AKIA***MPLE
        """
        pass


class BaseValidator(ABC):
    """
    Базовый класс для валидаторов секретов.

    Валидаторы проверяют формат найденных секретов и могут снижать
    риск для невалидных находок (например, неверный формат ключа).

    Цель валидации:
    - Снижение False Positives
    - Проверка соответствия ожидаемому формату
    - Дополнительная верификация без API-вызовов

    Attributes:
        None: Этот класс не имеет атрибутов, только методы

    Example:
        >>> class AWSKeyValidator(BaseValidator):
        ...     def validate(self, finding):
        ...         if finding.secret_type == "AWS_ACCESS_KEY_ID":
        ...             if not finding.value.startswith("AKIA"):
        ...                 finding.risk_score *= 0.3
        ...         return finding
    """

    @abstractmethod
    def validate(self, finding: Any) -> Any:
        """
        Валидирует формат найденного секрета.

        Проверяет что найденный секрет соответствует ожидаемому формату
        и при необходимости корректирует risk_score.

        Args:
            finding (Finding): Объект Finding содержащий информацию
                              о найденной уязвимости.

        Returns:
            Finding: Обновлённый объект Finding с возможными изменениями:
                - risk_score (float): Может быть снижен для невалидных форматов
                - risk_level (RiskLevel): Пересчитывается на основе risk_score
                - additional_data (dict): Может содержать информацию о валидации

        Example:
            >>> validator = AWSKeyValidator()
            >>> finding = Finding(secret_type="AWS_ACCESS_KEY_ID", value="INVALID")
            >>> validated = validator.validate(finding)
            >>> print(validated.risk_score)
            2.7  # Было 9.0, снижено в 3 раза
        """
        pass


class BaseReporter(ABC):
    """
    Базовый класс для репортёров (вывод результатов).

    Определяет контракт для всех репортёров которые форматируют
    и выводят результаты сканирования в различных форматах.

    Поддерживаемые форматы:
    - Console: Красивый вывод в терминал с цветами (Rich)
    - JSON: Машиночитаемый формат для интеграции
    - SARIF: Формат для GitHub Security Tab
    - Text: Plain text для сохранения в файл

    Attributes:
        None: Этот класс не имеет атрибутов, только методы

    Example:
        >>> class JSONReporter(BaseReporter):
        ...     def report(self, result, output_path=None):
        ...         data = result.to_dict()
        ...         json_str = json.dumps(data, indent=2)
        ...         if output_path:
        ...             with open(output_path, 'w') as f:
        ...                 f.write(json_str)
        ...         return json_str
    """

    @abstractmethod
    def report(self, result: Any, output_path: Path | str | None = None) -> str:
        """
        Форматирует и выводит результаты сканирования.

        Преобразует объект ScanResult в строковое представление
        заданного формата и опционально сохраняет в файл.

        Args:
            result (ScanResult): Результат сканирования содержащий
                               список находок и метаданные.
            output_path (Path | str | None): Путь для сохранения отчёта.
                                            Если None, вывод только в консоль.

        Returns:
            str: Сформированный отчёт в формате репортёра.
                - ConsoleReporter: Текст с ANSI-кодами цветов
                - JSONReporter: JSON строка
                - SARIFReporter: SARIF JSON
                - TextReporter: Plain text

        Raises:
            IOError: Если файл не может быть записан
            PermissionError: Если нет прав на запись в директорию

        Example:
            >>> reporter = JSONReporter()
            >>> report = reporter.report(result, 'results/scan.json')
            >>> print(f"Report saved, {len(report)} bytes")
            Report saved, 2048 bytes
        """
        pass