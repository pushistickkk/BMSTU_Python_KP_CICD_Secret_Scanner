"""Базовый класс для всех парсеров."""

from scanner.core.interfaces import BaseParser


class ParserMixin(BaseParser):
    """
    Базовая реализация общих методов парсеров.

    Будет:
        Загружать YAML через pyyaml
        Искать секции variables:, script:, image:
        Извлекать значения с контекстом: {stage: "deploy", job: "prod", section: "variables"}
    """

    def get_type(self):
        """Должен быть переопределён в наследниках."""
        raise NotImplementedError

    def parse(self, file_path):
        """Должен быть переопределён в наследниках."""
        raise NotImplementedError

    def get_all_values_with_context(self, config):
        """Должен быть переопределён в наследниках."""
        raise NotImplementedError