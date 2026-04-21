"""
Entropy Detector — поиск секретов через энтропию Шеннона.
Находит неизвестные форматы секретов по статистической случайности.
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
    Формула: H = -Σ p(x) × log₂(p(x))
    Где:
        p(x) — вероятность символа x в строке
        H > 4.0 — высокая энтропия (вероятно секрет)
        H < 3.0 — низкая энтропия (обычный текст)
    """
    def __init__(self, threshold: float = 4.0, min_length: int = 20):
        """
        Инициализирует детектор. 
        Args:
            threshold: Порог энтропии (рекомендуется 4.0)
            min_length: Минимальная длина строки для проверки
        """
        self.threshold = threshold
        self.min_length = min_length
    
    def get_priority(self) -> int:
        """Выполняется после regex детектора."""
        return 3
    
    def calculate_entropy(self, data: str) -> float:
        """
        Вычисляет энтропию Шеннона для строки.
        Args:
            data: Строка для анализа
        Returns:
            float: Энтропия от 0.0 до ~6.0 (для base64)
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
        Args:
            value: Строка для проверки
        Returns:
            bool: True если энтропия выше порога
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
        Args:
            value: Строка для проверки
        Returns:
            bool: True если это не секрет (хэш, ID, и т.д.)
        """
        value_lower = value.lower()
        
        # Очевидные не-секреты
        not_secret_patterns = [
            r'^sha256:',           # Хэш-префиксы
            r'^sha512:',
            r'^md5:',
            r'^build_',            # Build ID
            r'^v\d+\.\d+',         # Версии (for exp. - v1.2.3)
            r'^\d{4}-\d{2}-\d{2}', # Даты
            r'_config\.',          # Конфиг файлы
            r'\.yaml$',            # YAML расширения
            r'\.yml$',
            r'\.json$',
        ]
        
        for pattern in not_secret_patterns:
            if re.search(pattern, value_lower):
                return True
        
        # Слова с явным значением
        safe_words = ['config', 'build', 'version', 'release', 'test', 'dev', 'prod']
        if any(word in value_lower for word in safe_words):
            # Но только если это не единственное слово
            if len(value) > 30:
                return True
        
        return False
    
    def detect(
                self, 
                config: Any, 
                all_values: List[Tuple[str, str, Dict[str, Any]]]
            ) -> List[Finding]:
        """
        Ищет высокоэнтропийные строки.
        Args:
            config: Распарсенная конфигурация
            all_values: Список (key_path, value, context_dict)
        Returns:
            Список объектов Finding
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
                
                line_num = context_dict.pop('line', 0)

                finding = Finding(
                    file=config.file_path,
                    line=line_num,  # Прямо в Finding
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