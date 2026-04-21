"""
Entropy Detector — поиск секретов через энтропию Шеннона.

Этот модуль предоставляет класс EntropyDetector который находит
неизвестные форматы секретов по статистической случайности строки.

Формула энтропии Шеннона:
    H = -Σ p(x) × log₂(p(x))

Где:
    - p(x) — вероятность символа x в строке
    - H > 4.0 — высокая энтропия (вероятно секрет)
    - H < 3.0 — низкая энтропия (обычный текст)

Детектор применяется после RegexDetector для поиска секретов
неизвестных форматов которые не покрыты регулярными выражениями.
"""

import math
import re
from collections import Counter
from typing import List, Dict, Any, Tuple
from scanner.detectors.base import DetectorMixin
from scanner.core.models import Finding, PipelineContext
from scanner.detectors.regex import is_variable_reference


class EntropyDetector(DetectorMixin):
    """
    Детектор на основе энтропии Шеннона.

    Находит строки с высокой статистической случайностью которые
    могут быть секретами неизвестных форматов.

    Алгоритм работы:
    1. Фильтрует строки по минимальной длине (min_length)
    2. Проверяет что строка содержит только base64/hex символы
    3. Исключает очевидные не-секреты (хеши, версии, даты)
    4. Вычисляет энтропию Шеннона
    5. Сравнивает с порогом (threshold)

    Attributes:
        threshold (float): Порог энтропии для детекции (по умолчанию 4.0)
        min_length (int): Минимальная длина строки для проверки (по умолчанию 20)

    Example:
        >>> detector = EntropyDetector(threshold=4.0, min_length=20)
        >>> findings = detector.detect(config, values)
        >>> for f in findings:
        ...     print(f.secret_type, f.additional_data['entropy'])
        HIGH_ENTROPY_STRING 4.52
    """

    def __init__(self, threshold: float = 4.0, min_length: int = 20):
        """
        Инициализирует детектор энтропии.

        Args:
            threshold (float): Порог энтропии для детекции.
                             Значения >= 4.0 считаются высокоэнтропийными.
            min_length (int): Минимальная длина строки для проверки.
                             Короткие строки игнорируются.

        Example:
            >>> detector = EntropyDetector(threshold=4.5, min_length=25)
            >>> print(detector.threshold, detector.min_length)
            4.5 25
        """
        self.threshold = threshold
        self.min_length = min_length

    def get_priority(self) -> int:
        """
        Возвращает приоритет выполнения детектора.

        Returns:
            int: 3 (низкий приоритет — выполняется после Regex и Contextual)
        """
        return 3

    def calculate_entropy(self,  str) -> float:
        """
        Вычисляет энтропию Шеннона для строки.

        Формула: H = -Σ p(x) × log₂(p(x))

        Где:
            - p(x) = count(x) / len(data) — вероятность символа
            - Сумма берётся по всем уникальным символам в строке

        Диапазон значений:
            - 0.0: Все символы одинаковые (например, "aaaaaa")
            - ~6.0: Равномерное распределение (например, base64)

        Args:
             Строка для анализа

        Returns:
            float: Энтропия в диапазоне [0.0, ~6.0]

        Example:
            >>> detector = EntropyDetector()
            >>> print(f"{detector.calculate_entropy('aaaaaa'):.2f}")
            0.00
            >>> print(f"{detector.calculate_entropy('aB3dE6gH9jK2'):.2f}")
            3.58
        """
        if not data:
            return 0.0

        entropy = 0.0
        counter = Counter(data)
        length = len(data)

        for count in counter.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy

    def is_high_entropy(self, value: str) -> bool:
        """
        Проверяет, является ли строка высокоэнтропийной.

        Критерии детекции:
        1. Длина строки >= min_length
        2. Строка содержит только base64/hex символы [A-Za-z0-9+/=_-]
        3. Строка не является очевидным не-секретом
        4. Энтропия Шеннона >= threshold

        Args:
            value (str): Строка для проверки

        Returns:
            bool: True если строка считается высокоэнтропийной

        Example:
            >>> detector = EntropyDetector()
            >>> detector.is_high_entropy("wJalrXUtnFEMI/K7MDENG")
            True
            >>> detector.is_high_entropy("configuration_value")
            False
        """
        if len(value) < self.min_length:
            return False

        # Фильтр: только base64/hex-подобные строки
        if not re.match(r'^[A-Za-z0-9+/=_-]+$', value):
            return False

        # Исключаем очевидные не-секреты
        if self._is_likely_not_secret(value):
            return False

        entropy = self.calculate_entropy(value)
        return entropy >= self.threshold

    def _is_likely_not_secret(self, value: str) -> bool:
        """
        Проверяет, является ли строка очевидным не-секретом.

        Фильтрует ложные срабатывания на:
        - Хэш-префиксы (sha256:, md5:, sha512:)
        - Build ID (build_*)
        - Версии (v1.2.3)
        - Даты (2024-01-15)
        - Конфиг файлы (*_config.*, *.yaml, *.yml, *.json)
        - Слова с явным значением (config, build, version, etc.)

        Args:
            value (str): Строка для проверки

        Returns:
            bool: True если строка считается не-секретом

        Example:
            >>> detector = EntropyDetector()
            >>> detector._is_likely_not_secret("sha256:abc123")
            True
            >>> detector._is_likely_not_secret("wJalrXUtnFEMI")
            False
        """
        value_lower = value.lower()

        # Очевидные не-секреты (хеши, ID, версии, даты, конфиги)
        not_secret_patterns = [
            r'^sha256:',  # Хэш-префиксы
            r'^sha512:',
            r'^md5:',
            r'^build_',  # Build ID
            r'^v\d+\.\d+',  # Версии (v1.2.3)
            r'^\d{4}-\d{2}-\d{2}',  # Даты
            r'_config\.',  # Конфиг файлы
            r'\.yaml$',  # YAML расширения
            r'\.yml$',
            r'\.json$',
        ]

        for pattern in not_secret_patterns:
            if re.search(pattern, value_lower):
                return True

        # Слова с явным значением
        safe_words = ['config', 'build', 'version', 'release', 'test', 'dev', 'prod']
        if any(word in value_lower for word in safe_words):
            # Но только если это не единственное слово (длина > 30)
            if len(value) > 30:
                return True

        return False

    def detect(
        self,
        config: Any,
        all_values: List[Tuple[str, str, Dict[str, Any]]]
    ) -> List[Finding]:
        """
        Ищет высокоэнтропийные строки в предоставленных значениях.

        Алгоритм:
        1. Проходит по всем строковым значениям
        2. Пропускает переменные окружения ($VAR, ${{ secrets.* }})
        3. Проверяет энтропию через is_high_entropy()
        4. Создаёт Finding с типом "HIGH_ENTROPY_STRING"

        Args:
            config: Распарсенная конфигурация (используется для file_path)
            all_values (List[tuple]): Список кортежей (key_path, value, context_dict)

        Returns:
            List[Finding]: Список найденных высокоэнтропийных строк

        Example:
            >>> detector = EntropyDetector()
            >>> findings = detector.detect(config, values)
            >>> for f in findings:
            ...     print(f.secret_type, f.value[:20])
            HIGH_ENTROPY_STRING wJalrXUtnFEMI/K7MD...
        """
        findings = []

        for key_path, value, context_dict in all_values:
            if not isinstance(value, str):
                continue

            # Пропускаем переменные окружения
            if is_variable_reference(value):
                continue

            # Проверяем энтропию
            if self.is_high_entropy(value):
                entropy = self.calculate_entropy(value)

                # Извлекаем номер строки из context_dict
                line_num = context_dict.pop('line', 0)

                finding = Finding(
                    file=config.file_path,
                    line=line_num,
                    secret_type="HIGH_ENTROPY_STRING",
                    value=value,
                    redacted_value=value[:4] + '*' * (len(value) - 8) + value[-4:],
                    is_hardcoded=True,
                    context=PipelineContext(**context_dict),
                    risk_score=4.0,
                    additional_data={"entropy": round(entropy, 2)},
                    detector_name="EntropyDetector",
                )
                findings.append(finding)

        return findings