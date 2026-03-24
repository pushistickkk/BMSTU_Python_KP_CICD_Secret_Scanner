"""Базовый класс для всех репортёров."""

from scanner.core.interfaces import BaseReporter


class ReporterMixin(BaseReporter):
    """
    Базовая реализация общих методов репортёров.
    """

    def report(self, result, output_path=None):
        """Должен быть переопределён в наследниках."""
        raise NotImplementedError