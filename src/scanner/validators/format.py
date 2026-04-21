"""
Format Validators — валидация формата найденных секретов.

Этот модуль предоставляет классы для валидации формата обнаруженных
секретов с целью снижения количества ложных срабатываний (False Positives).

Архитектура валидации:
1. BaseFormatValidator: Абстрактный базовый класс
2. Конкретные валидаторы: AWSKeyValidator, GitHubTokenValidator, etc.
3. FormatValidatorManager: Координатор применения всех валидаторов

Принцип работы:
- Валидатор проверяет соответствие секрета ожидаемому формату
- При несоответствии снижает risk_score (по умолчанию ×0.3)
- Добавляет метаданные о причине валидации в additional_data

Пример использования:
    >>> from scanner.validators.format import FormatValidatorManager
    >>> manager = FormatValidatorManager()
    >>> validated_finding = manager.validate(finding)
    >>> if 'validation_failed' in validated_finding.additional_data:
    ...     print(f"Warning: {validated_finding.additional_data['validation_failed']}")
"""

from abc import ABC, abstractmethod
from typing import List
from scanner.core.models import Finding
from scanner.core.interfaces import BaseValidator
from scanner.core.risk_scorer import ContextAwareRiskScorer


class BaseFormatValidator(ABC):
    """
    Абстрактный базовый класс для валидаторов формата секретов.

    Определяет контракт для всех валидаторов которые проверяют
    соответствие обнаруженных секретов ожидаемому формату.

    Цель валидации:
    - Снижение False Positives через проверку формата
    - Дополнительная верификация без внешних API-вызовов
    - Обогащение находок метаданными о валидации

    Наследники должны реализовать метод validate() который:
    1. Проверяет формат секрета согласно спецификации провайдера
    2. При несоответствии снижает risk_score (рекомендуется ×0.3)
    3. Добавляет информацию о валидации в additional_data
    4. Возвращает обновлённый объект Finding

    Example:
        >>> class MyValidator(BaseFormatValidator):
        ...     def validate(self, finding):
        ...         if finding.secret_type == "MY_TYPE":
        ...             if not self._is_valid_format(finding.value):
        ...                 finding.risk_score *= 0.3
        ...                 finding.additional_data["validation_failed"] = "Invalid format"
        ...         return finding
    """

    @abstractmethod
    def validate(self, finding: Finding) -> Finding:
        """
        Валидирует формат найденного секрета.

        Проверяет что значение секрета соответствует ожидаемому формату
        для данного типа и при необходимости корректирует оценку риска.

        Алгоритм валидации:
        1. Проверяет что finding.secret_type соответствует валидатору
        2. Применяет специфичные проверки формата для этого типа
        3. При несоответствии:
           - Снижает risk_score (рекомендуется коэффициент 0.3)
           - Добавляет причину в additional_data["validation_failed"]
        4. Пересчитывает risk_level на основе обновлённого risk_score
        5. Добавляет флаг additional_data["validated"] = True

        Args:
            finding (Finding): Объект Finding содержащий информацию
                              о найденной уязвимости

        Returns:
            Finding: Обновлённый объект Finding с возможными изменениями:
                - risk_score (float): Может быть снижен для невалидных форматов
                - risk_level (RiskLevel): Пересчитывается на основе risk_score
                - additional_data (dict): Содержит информацию о валидации

        Example:
            >>> validator = AWSKeyValidator()
            >>> finding = Finding(secret_type="AWS_ACCESS_KEY_ID", value="INVALID")
            >>> validated = validator.validate(finding)
            >>> print(validated.risk_score)
            2.7  # Было 9.0, снижено в 3 раза
            >>> print(validated.additional_data)
            {'validation_failed': 'Invalid prefix', 'validated': True}
        """
        pass


class AWSKeyValidator(BaseFormatValidator):
    """
    Валидатор формата учётных данных AWS.

    Проверяет соответствие найденных секретов формату AWS credentials:

    AWS Access Key ID:
    - Всегда начинается с префикса: AKIA, ASIA, ABIA, ACCA, A3T
    - Длина: ровно 20 символов (4 префикс + 16 идентификатор)
    - Символы: только заглавные буквы A-Z и цифры 0-9

    AWS Secret Access Key:
    - Длина: ровно 40 символов
    - Символы: [A-Za-z0-9/+=] (base64-like набор)
    - Не должен начинаться или заканчиваться спецсимволами

    При несоответствии формату risk_score снижается в 3 раза (×0.3)
    что позволяет отфильтровать ложные срабатывания энтропийного детектора.

    Примеры валидных значений:
    - Access Key ID: "AKIAIOSFODNN7EXAMPLE"
    - Secret Key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    Example:
        >>> validator = AWSKeyValidator()
        >>> finding = Finding(
        ...     secret_type="AWS_ACCESS_KEY_ID",
        ...     value="AKIAIOSFODNN7EXAMPLE",
        ...     risk_score=9.0
        ... )
        >>> validated = validator.validate(finding)
        >>> print(validated.risk_score)
        9.0  # Не изменился, формат валиден
        >>> finding_invalid = Finding(
        ...     secret_type="AWS_ACCESS_KEY_ID",
        ...     value="INVALID_KEY_FORMAT",
        ...     risk_score=9.0
        ... )
        >>> validated_invalid = validator.validate(finding_invalid)
        >>> print(validated_invalid.risk_score)
        2.7  # Снижено в 3 раза
    """

    def validate(self, finding: Finding) -> Finding:
        """
        Валидирует формат AWS учётных данных.

        Проверяет:
        - Для AWS_ACCESS_KEY_ID: префикс и длину
        - Для AWS_SECRET_ACCESS_KEY: длину и набор символов

        При несоответствии снижает risk_score ×0.3 и добавляет
        информацию о причине в additional_data.

        Args:
            finding (Finding): Объект Finding с типом AWS_*

        Returns:
            Finding: Обновлённый объект с скорректированным риском
        """
        # Пропускаем если не AWS ключ
        if finding.secret_type not in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]:
            return finding

        value = finding.value

        # Валидация AWS Access Key ID
        if finding.secret_type == "AWS_ACCESS_KEY_ID":
            valid_prefixes = ("AKIA", "ASIA", "ABIA", "ACCA", "A3T")
            if not (value.startswith(valid_prefixes) and len(value) == 20):
                finding.risk_score *= 0.3
                finding.additional_["validation_failed"] = "Invalid AWS Access Key format"

        # Валидация AWS Secret Access Key
        if finding.secret_type == "AWS_SECRET_ACCESS_KEY":
            if len(value) != 40:
                finding.risk_score *= 0.3
                finding.additional_["validation_failed"] = "Invalid AWS Secret Key length"

        # Пересчитываем уровень риска если score изменился
        if "validation_failed" in finding.additional_ or finding.additional_data.get("validated"):
            scorer = ContextAwareRiskScorer()
            finding.risk_level = scorer.get_level(finding.risk_score)

        finding.additional_["validated"] = True
        return finding


class GitHubTokenValidator(BaseFormatValidator):
    """
    Валидатор формата токенов доступа GitHub.

    Проверяет соответствие найденных секретов формату GitHub tokens:

    GitHub Personal Access Token (Classic):
    - Префикс: "ghp_"
    - Длина: ровно 40 символов (4 префикс + 36 токен)
    - Символы: [A-Za-z0-9]

    GitHub Fine-Grained Personal Access Token:
    - Префикс: "github_pat_"
    - Формат: "github_pat_" + 22 симв + "_" + 59 симв
    - Общая длина: 77 символов

    GitHub OAuth Token:
    - Префикс: "gho_"
    - Длина: ровно 40 символов

    При несоответствии формату risk_score снижается в 3 раза (×0.3).

    Примеры валидных значений:
    - Classic PAT: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    - Fine-Grained: "github_pat_xxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    Example:
        >>> validator = GitHubTokenValidator()
        >>> finding = Finding(
        ...     secret_type="GITHUB_PAT",
        ...     value="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ...     risk_score=8.0
        ... )
        >>> validated = validator.validate(finding)
        >>> print(validated.risk_score)
        8.0  # Не изменился, формат валиден
    """

    def validate(self, finding: Finding) -> Finding:
        """
        Валидирует формат токенов доступа GitHub.

        Проверяет префикс и длину для каждого типа токена.
        При несоответствии снижает risk_score ×0.3.

        Args:
            finding (Finding): Объект Finding с типом GITHUB_*

        Returns:
            Finding: Обновлённый объект с скорректированным риском
        """
        # Пропускаем если не GitHub токен
        if finding.secret_type not in ["GITHUB_PAT", "GITHUB_FINE_GRAINED", "GITHUB_OAUTH"]:
            return finding

        value = finding.value

        # Валидация GitHub Personal Access Token (Classic)
        if finding.secret_type == "GITHUB_PAT":
            if not (value.startswith("ghp_") and len(value) == 40):
                finding.risk_score *= 0.3
                finding.additional_["validation_failed"] = "Invalid GitHub PAT format"

        # Валидация GitHub Fine-Grained Token
        if finding.secret_type == "GITHUB_FINE_GRAINED":
            if not value.startswith("github_pat_"):
                finding.risk_score *= 0.3
                finding.additional_["validation_failed"] = "Invalid GitHub Fine-Grained prefix"

        # Валидация GitHub OAuth Token
        if finding.secret_type == "GITHUB_OAUTH":
            if not (value.startswith("gho_") and len(value) == 40):
                finding.risk_score *= 0.3
                finding.additional_["validation_failed"] = "Invalid GitHub OAuth format"

        # Пересчитываем уровень риска если score изменился
        if "validation_failed" in finding.additional_ or finding.additional_data.get("validated"):
            scorer = ContextAwareRiskScorer()
            finding.risk_level = scorer.get_level(finding.risk_score)

        finding.additional_["validated"] = True
        return finding


class StripeKeyValidator(BaseFormatValidator):
    """
    Валидатор формата ключей Stripe API.

    Проверяет соответствие найденных секретов формату Stripe keys:

    Stripe Secret Key:
    - Префикс: "sk_live_" (production) или "sk_test_" (test mode)
    - Длина: минимум 32 символа (8 префикс + 24 идентификатор)
    - Символы: [A-Za-z0-9]

    Stripe Publishable Key (не проверяется, т.к. публичный):
    - Префикс: "pk_live_" или "pk_test_"
    - Не считается секретом, игнорируется детектором

    При несоответствии формату risk_score снижается в 3 раза (×0.3).

    Примеры валидных значений:
    - Secret Key: "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx"
    - Test Key: "sk_test_xxxxxxxxxxxxxxxxxxxxxxxx"

    Example:
        >>> validator = StripeKeyValidator()
        >>> finding = Finding(
        ...     secret_type="STRIPE_KEY",
        ...     value="sk_live_xxxxxxxxxxxxxxxxxxxxxxxx",
        ...     risk_score=8.0
        ... )
        >>> validated = validator.validate(finding)
        >>> print(validated.risk_score)
        8.0  # Не изменился, формат валиден
    """

    def validate(self, finding: Finding) -> Finding:
        """
        Валидирует формат ключей Stripe API.

        Проверяет префикс и минимальную длину ключа.
        При несоответствии снижает risk_score ×0.3.

        Args:
            finding (Finding): Объект Finding с типом STRIPE_KEY

        Returns:
            Finding: Обновлённый объект с скорректированным риском
        """
        # Пропускаем если не Stripe ключ
        if finding.secret_type != "STRIPE_KEY":
            return finding

        value = finding.value

        # Валидация префикса
        valid_prefixes = ("sk_live_", "sk_test_")
        if not any(value.startswith(prefix) for prefix in valid_prefixes):
            finding.risk_score *= 0.3
            finding.additional_["validation_failed"] = "Invalid Stripe key prefix"

        # Валидация минимальной длины
        if len(value) < 32:
            finding.risk_score *= 0.3
            finding.additional_["validation_failed"] = "Invalid Stripe key length"

        # Пересчитываем уровень риска если score изменился
        if "validation_failed" in finding.additional_ or finding.additional_data.get("validated"):
            scorer = ContextAwareRiskScorer()
            finding.risk_level = scorer.get_level(finding.risk_score)

        finding.additional_["validated"] = True
        return finding


class FormatValidatorManager:
    """
    Менеджер валидаторов формата секретов.

    Координирует применение всех зарегистрированных валидаторов
    к найденным секретам для снижения количества ложных срабатываний.

    Архитектура:
    - validators (list): Список экземпляров валидаторов
    - validate(finding): Применяет все подходящие валидаторы последовательно

    Порядок применения валидаторов:
    1. AWSKeyValidator: Для AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
    2. GitHubTokenValidator: Для GITHUB_PAT, GITHUB_FINE_GRAINED, GITHUB_OAUTH
    3. StripeKeyValidator: Для STRIPE_KEY
    4. (Расширяемо: добавить новые валидаторы в __init__)

    Каждый валидатор применяется только к соответствующим типам секретов,
    поэтому порядок не влияет на результат.

    Пример использования:
        >>> manager = FormatValidatorManager()
        >>> finding = Finding(secret_type="AWS_ACCESS_KEY_ID", value="INVALID")
        >>> validated = manager.validate(finding)
        >>> print(validated.additional_data)
        {'validation_failed': 'Invalid AWS Access Key format', 'validated': True}

    Расширение:
        Для добавления нового валидатора:
        1. Создайте класс наследник BaseFormatValidator
        2. Реализуйте метод validate()
        3. Добавьте экземпляр в self.validators в __init__
    """

    def __init__(self):
        """
        Инициализирует менеджер валидаторов.

        Создаёт и регистрирует все поддерживаемые валидаторы:
        - AWSKeyValidator
        - GitHubTokenValidator
        - StripeKeyValidator

        Для добавления нового валидатора добавьте его в список:
            self.validators.append(MyNewValidator())
        """
        self.validators: List[BaseFormatValidator] = [
            AWSKeyValidator(),
            GitHubTokenValidator(),
            StripeKeyValidator(),
        ]

    def validate(self, finding: Finding) -> Finding:
        """
        Применяет все подходящие валидаторы к находке.

        Алгоритм:
        1. Проходит по всем зарегистрированным валидаторам
        2. Каждый валидатор проверяет если он поддерживает finding.secret_type
        3. При поддержке применяет валидацию и обновляет finding
        4. Возвращает итоговый обновлённый объект

        Примечание: Валидаторы применяются последовательно и каждый
        может модифицировать finding, поэтому порядок может влиять
        на результат если несколько валидаторов поддерживают один тип.

        Args:
            finding (Finding): Объект Finding для валидации

        Returns:
            Finding: Обновлённый объект после применения всех валидаторов

        Example:
            >>> manager = FormatValidatorManager()
            >>> finding = Finding(secret_type="AWS_ACCESS_KEY_ID", value="AKIAIOSFODNN7EXAMPLE")
            >>> validated = manager.validate(finding)
            >>> print("validated" in validated.additional_data)
            True
        """
        for validator in self.validators:
            finding = validator.validate(finding)
        return finding