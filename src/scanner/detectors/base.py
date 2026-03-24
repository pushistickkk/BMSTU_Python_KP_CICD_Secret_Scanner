"""Базовый класс для всех детекторов."""

from scanner.core.interfaces import BaseDetector


class DetectorMixin(BaseDetector):
    """
    Базовая реализация общих методов детекторов.

    Наследуйтесь от этого класса вместо прямого наследования от BaseDetector.
    """

    def get_priority(self) -> int:
        """Должен быть переопределён в наследниках."""
        raise NotImplementedError

    def detect(self, config, all_values):
        """Должен быть переопределён в наследниках."""
        raise NotImplementedError