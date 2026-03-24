"""
Базовые интерфейсы для модулей сканера.
"""

from abc import ABC, abstractmethod
from typing import List, Any, Dict
from pathlib import Path


class BaseParser(ABC):
    """
    The base class for CI/CD configuration parsers.

    Each parser should be able to:
    - Identify the type of CI/CD system
    - Parse the file into a structured object
    - Extract all values with context

    *****

    Базовый класс для парсеров CI/CD конфигураций.

    Каждый парсер должен уметь:
    - Определить тип CI/CD системы
    - Распарсить файл в структурированный объект
    - Извлечь все значения с контекстом

    * любой парсер/детектор/репортёр должен реализовать определённые тут методы
        гарантирует что все парсеры имеют одинаковый интерфейс
    """

    @abstractmethod # метод обязан быть переопределён в наследнике.
    def get_type(self) -> str:
        """
        Возвращает тип CI/CD системы.

        Returns:
            str: 'gitlab', 'github', 'jenkins', etc.
        """
        pass

    @abstractmethod
    def parse(self, file_path: Path | str) -> Any:
        """
        Парсит файл конфигурации.

        Args:
            file_path: Путь к файлу конфигурации

        Returns:
            Структурированный объект конфигурации
        """
        pass

    @abstractmethod
    def get_all_values_with_context(
            self,
            config: Any
    ) -> List[tuple[str, str, Dict[str, Any]]]:
        """
        Извлекает все строковые значения с контекстом.

        Args:
            config: Распарсенная конфигурация

        Returns:
            Список кортежей (key_path, value, context_dict)
            где context_dict содержит: stage, job, environment, etc.
        """
        pass


class BaseDetector(ABC):
    """
    the base class for secret detectors.

    Each detector should be able to:
        - Determine the priority of execution
        - Find secrets in the data

    *****

    Базовый класс для детекторов секретов.

    Каждый детектор должен уметь:
    - Определить приоритет выполнения
    - Найти секреты в данных
    """

    @abstractmethod
    def get_priority(self) -> int:
        """
        Возвращает приоритет выполнения детектора.

        Returns:
            int: 1 = высокий приоритет, 5 = низкий
        """
        pass

    @abstractmethod
    def detect(
            self,
            config: Any,
            all_values: List[tuple[str, str, Dict[str, Any]]]
    ) -> List[Any]:
        """
        Detects secrets in the provided values.

        Args:
            config: Распарсенная конфигурация
            all_values: Список (key_path, value, context)

        Returns:
            Список объектов Finding
        """
        pass


class BaseValidator(ABC):
    """
    Базовый класс для валидаторов секретов.

    Валидаторы проверяют формат и могут снижать риск
    для невалидных находок.
    """

    @abstractmethod
    def validate(self, finding: Any) -> Any:
        """
        Валидирует найденный секрет.

        Args:
            finding: Объект Finding

        Returns:
            Обновлённый объект Finding (с изменённым risk_score)
        """
        pass


class BaseReporter(ABC):
    """
    Базовый класс для репортёров (вывод результатов).

    Каждый репортёр должен уметь выводить результаты
    в своём формате (console, JSON, SARIF, etc.)
    """

    @abstractmethod
    def report(self, result: Any, output_path: Path | str | None = None) -> str:
        """
        Выводит результаты сканирования.

        Args:
            result: Объект ScanResult
            output_path: Путь для сохранения (опционально)

        Returns:
            str: Сформированный отчёт
        """
        pass