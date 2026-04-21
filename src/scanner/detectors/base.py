"""
Базовый класс для всех детекторов.

Этот модуль предоставляет класс-миксин DetectorMixin который реализует
абстрактный интерфейс BaseDetector. Наследование от этого класса
гарантирует что все детекторы имеют одинаковый интерфейс.
"""

from scanner.core.interfaces import BaseDetector


class DetectorMixin(BaseDetector):
    """
    Базовая реализация общих методов детекторов.

    Наследуйтесь от этого класса вместо прямого наследования от BaseDetector.
    Это обеспечивает единообразие интерфейса и упрощает тестирование.

    Все методы в этом классе должны быть переопределены в наследниках.
    Попытка вызвать непереопределённый метод вызовет NotImplementedError.

    Example:
        >>> class MyDetector(DetectorMixin):
        ...     def get_priority(self) -> int:
        ...         return 2
        ...     def detect(self, config, all_values):
        ...         return []  # Логика детекции
    """

    def get_priority(self) -> int:
        """
        Возвращает приоритет выполнения детектора.

        Должен быть переопределён в наследниках.

        Шкала приоритетов:
            1: Высокий (RegexDetector) — выполняется первым
            2: Средний (ContextualDetector) — обогащает находки
            3: Низкий (EntropyDetector) — ищет неизвестные форматы

        Returns:
            int: Приоритет от 1 (высокий) до 5 (низкий)

        Raises:
            NotImplementedError: Если метод не переопределён

        Example:
            >>> detector = RegexDetector()
            >>> detector.get_priority()
            1
        """
        raise NotImplementedError

    def detect(self, config, all_values):
        """
        Ищет секреты в предоставленных значениях.

        Должен быть переопределён в наследниках.

        Args:
            config: Распарсенная конфигурация (тип зависит от парсера)
            all_values (List[tuple]): Список кортежей (key_path, value, context)

        Returns:
            List[Finding]: Список найденных уязвимостей

        Raises:
            NotImplementedError: Если метод не переопределён

        Example:
            >>> detector = RegexDetector()
            >>> findings = detector.detect(config, values)
            >>> print(len(findings))
            2
        """
        raise NotImplementedError