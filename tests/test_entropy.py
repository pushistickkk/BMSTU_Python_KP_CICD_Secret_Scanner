"""Тесты для Entropy Detector
pytest tests/test_entropy.py tests/test_validators.py -v
"""

import pytest
from scanner.detectors.entropy import EntropyDetector


@pytest.fixture
def detector():
    return EntropyDetector(threshold=4.0, min_length=20)


def test_high_entropy_detection(detector):
    """Проверяет обнаружение высокоэнтропийных строк."""
    # Высокая энтропия (секреты)
    assert detector.is_high_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") == True 
    assert detector.is_high_entropy("ghp_AHbctyskqP8jsmnwjwllck") == True
    
    # Низкая энтропия (не секреты)
    assert detector.is_high_entropy("aaaaaaaaaaaaaaaaaaaa") == False
    assert detector.is_high_entropy("12345678901234567890") == False
    assert detector.is_high_entropy("configuration_value") == False


def test_entropy_calculation(detector):
    """Проверяет расчёт энтропии."""
    # Равномерное распределение = высокая энтропия
    assert detector.calculate_entropy("aAbBcCdD") > 2.5
    
    # Один символ = низкая энтропия
    assert detector.calculate_entropy("aaaaaaaa") == 0.0
    
    # Пустая строка
    assert detector.calculate_entropy("") == 0.0


def test_is_likely_not_secret(detector):
    """Проверяет фильтр очевидных не-секретов."""
    assert detector._is_likely_not_secret("sha256:abc123") == True
    assert detector._is_likely_not_secret("build_12345") == True
    assert detector._is_likely_not_secret("v1.2.3") == True
    assert detector._is_likely_not_secret("wJalrXUtnFEMI/K7MDENG") == False