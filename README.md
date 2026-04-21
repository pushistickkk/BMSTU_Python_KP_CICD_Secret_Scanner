# CI/CD Secret Scanner

**Context-aware сканер секретов для конфигураций CI/CD с риск-скорингом и детекцией по нескольким движкам.**

---

## Содержание

- [Возможности](#-возможности)
- [Установка](#-установка)
- [Быстрый старт](#-быстрый-старт)
- [Поддерживаемые CI/CD системы](#-поддерживаемые-cicd-системы)
- [Типы обнаруживаемых секретов](#-типы-обнаруживаемых-секретов)
- [Команды и опции](#-команды-и-опции)
- [Форматы отчётов](#-форматы-отчётов)
- [Архитектура](#-архитектура)
- [Расширение функциональности](#-расширение-функциональности)
<!-- - [Примеры использования](#-примеры-использования)
- [Сравнение с аналогами](#-сравнение-с-аналогами) -->
---

## Возможности

| Функция | Описание |
|---------|----------|
| **Multi-platform** | Поддержка GitLab CI, GitHub Actions |
| **Multi-detector** | Regex + Entropy + Contextual анализ |
| **Risk Scoring** | Многофакторная оценка риска (stage × environment × secret_type) |
| **Line Numbers** | Точные номера строк с уязвимостями |
| **Detector Tags** | Информация каким движком найдена уязвимость |
| **Multiple Formats** | Console, JSON, SARIF, Text |
| **Auto-save** | Автоматическое сохранение в `results/` |
| **Pre-commit Hook** | Интеграция в CI/CD пайплайн |

---

## Установка

### Требования

- Python 3.10 или выше

### Установка из репозитория

```bash
# Клонируйте репозиторий
git clone https://github.com/yourusername/cicd-secret-scanner.git
cd cicd-secret-scanner

# Создай виртуальное окружение
python -m venv venv

# Активируйте окружение
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Установите зависимости
pip install -e .
```

### Проверка установки
```bash

# Проверьте что сканер доступен
cicd-scanner --help

# Ожидаемый вывод:
# Usage: cicd-scanner [OPTIONS] COMMAND [ARGS]...
# CI/CD Secret Scanner — context-aware secret scanner...
```

##  Быстрый старт
###  Сканирование одного файла
```bash
# GitLab CI
cicd-scanner scan .gitlab-ci.yml

# GitHub Actions
cicd-scanner scan .github/workflows/deploy.yml

```
###  Сканирование директории
```bash
# Сканировать все CI/CD файлы в директории
cicd-scanner scan ./ci-configs/

# Сканировать весь репозиторий
cicd-scanner scan ./my-project/
```

###  Сохранение отчёта
```bash
# Автоматическое имя файла (results/<timestamp>.text)
cicd-scanner scan ./ci-configs/

# Своё имя файла
cicd-scanner scan ./ci-configs/ --output my_report.json

# Своя директория
cicd-scanner scan ./ci-configs/ --output-dir reports/
```

##  Поддерживаемые CI/CD системы
###  GitLab CI
#### Файлы: .gitlab-ci.yml, .gitlab/ci/*.yml
#### Что анализируется:
  - Глобальные переменные (variables:)
  - Переменные джоб (jobs[].variables:)
  - Скрипты (jobs[].script:)
  - Окружения (jobs[].environment:)

#### Пример уязвимости:
```yaml
# .gitlab-ci.yml
variables:
  AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE"  # Найдёт!
  AWS_SECRET_ACCESS_KEY: $AWS_SECRET         # Пропустит (переменная)

deploy:
  stage: deploy
  environment: production
  script:
    - aws s3 sync ./dist s3://bucket/
```

###  GitHub Actions
#### Файлы: .gitlab-ci.yml, .gitlab/ci/*.yml
#### Что анализируется:
  - Глобальные env (env:)
  - Переменные джоб (jobs[].env:)
  - Переменные шагов (jobs[].steps[].env:)
  - Аргументы действий (jobs[].steps[].with:)
  - Скрипты (jobs[].steps[].run:)
  - Окружения (jobs[].environment:)

#### Пример уязвимости:
```yaml
# .github/workflows/deploy.yml
name: Deploy

env:
  STRIPE_KEY: "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx"  # Найдёт!

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy
        run: curl -H "Authorization: ghp_xxx..." https://api.github.com  # Найдёт!
        env:
          AWS_KEY: ${{ secrets.AWS_KEY }}  # Пропустит (secrets)
```

## Типы обнаруживаемых секретов
### Cloud Credentials (Облачные провайдеры)

| Тип секрета | Паттерн | Пример | Риск | 
|-------------|---------|--------|------|
| **AWS Access Key ID** | (AKIA`\|ASIA\|ABIA\|ACCA)[A-Z0-9]{16} | AKIAIOSFODNN7EXAMPLE | 9.0 |
| **AWS Secret Access Key** | [A-Za-z0-9/+=]{40} | wJalrXUtnFEMI/K7MDENG/... |  10.0 |

---
### Version Control Tokens (Системы контроля версий)

| Тип секрета | Паттерн | Пример | Риск | 
|-------------|---------|--------|------|
| **GitHub PAT** | ghp_[A-Za-z0-9]{36} | ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx | 8.0 |
| **GitHub Fine-Grained** | github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59} | github_pat_xxx_xxx |  7.0 |
| **GitLab PAT** | glpat-[A-Za-z0-9-]{20,} | glpat-xxxxxxxxxxxxxxxxxxxx |  8.0 |

---
### Database Credentials (Базы данных)

| Тип секрета | Паттерн | Пример | Риск | 
|-------------|---------|--------|------|
| **PostgreSQL URL** | postgres://[^:]+:[^@]+@ | postgresql://user:pass@host/db | 9.0 |
| **MySQL URL** | mysql://[^:]+:[^@]+@ | mysql://root:pass@host/db |  9.0 |
| **MongoDB URI** | mongodb://[^:]+:[^@]+@ | mongodb://user:pass@host/db |  9.0 |
| **Redis URL** | redis://:password@host | redis://:pass@host:6379 |  7.0 |

---
### Private Keys (Приватные ключи)

| Тип секрета | Паттерн | Пример | Риск | 
|-------------|---------|--------|------|
| **RSA Private Key** | -----BEGIN RSA PRIVATE KEY----- | pPEM формат | 10.0 |
| **OpenSSH Key** | -----BEGIN OPENSSH PRIVATE KEY----- | OpenSSH формат |  10.0 |
| **EC Private Key** | -----BEGIN EC PRIVATE KEY----- | EC формат |  10.0 |

---

### Private Keys (Приватные ключи)

| Тип секрета | Паттерн | Пример | Риск | 
|-------------|---------|--------|------|
| **Slack Token** | xox[baprs]-[0-9-]+-[a-zA-Z0-9]+ | xoxb-123456789012-... | 5.0 |
| **Stripe Key** | sk_live_[A-Za-z0-9]{24} | sk_live_xxxxxxxxxxxxxxxxxxxxxxxx |  8.0 |
| **SendGrid Key** | SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43} | SG.xxx.xxx |  6.0 |
| **Twilio Token** | SK[A-Za-z0-9]{32} | SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |  6.0 |

---

### Generic Secrets (Общие секреты)

| Тип секрета | Паттерн | Пример | Риск | 
|-------------|---------|--------|------|
| **Password Field** | (password|passwd|pwd)\s*[:=]\s*\S+ | password: mysecret123 | 5.0 |
| **Password Field** | (token|api_key)\s*[:=]\s*\S+ | token: abc123xyz |  5.0 |
| **High Entropy** | Энтропия Шеннона ≥ 4. | aB3dE6gH9jK2mN5pQ8sT |  4.0 |
---

## Формула риск-скоринга

```
Risk = Base(secret_type) × Stage(stage) × Environment(env) × Hardcoded(is_hardcoded)
```
### Базовые веса (Base)

---
| Тип секрета | Base Score
|-------------|---------|
| **AWS Secret Key** | 10.0
| **Private Key** | 10.0
| **Database URL** | 9.0
| **GitHub/GitLab PAT** | 9.0
| **Stripe Key** | 8.0
| **SendGrid Key** | 6.0
| **Slack Tokend** | 5.0
| **AWS Secret Key** | 5.0 

---

### Множители этапа (Stage)

---
| Этап | Множитель
|-------------|---------|
| **deploy/release/publish** | ×2.0
| **build** | ×1.0
| **test** | ×0.7
| **lint** | ×0.5

---

### Множители окружения (Environment)

---
| Этап | Множитель
|-------------|---------|
| **production/prod** | ×2.0
| **main/master** | ×1.8
| **staging/stage** | ×1.3
| **development/dev** | ×0.7
| **test** | ×0.5

---

### Итоговые уровни риска

---
| Risk Score | Уровень
|-------------|---------|
| **8.5 - 10.0** | CRITICAL
| **6.5 - 8.4** | HIGH
| **4.0 - 6.4** | MEDIUM
| **0.0 - 3.9** | LOW

---

## Команды и опции

#### Основная команда

```bash
cicd-scanner scan <PATH> [OPTIONS]
```

---

### Опции

| Опция | Короткая | Описание | По умолчанию | 
|-------------|---------|--------|------|
| **--format** | -f | Формат вывода (text/json/sarif) | text |
| **--output** | -o | Путь для сохранения отчёта |  results/<timestamp>.<format> |
| **--output-dir** | - | Директория для отчётов |  results/ |
| **--risk-threshold** | - | Минимальный уровень риска |  medium |
| **--fail-on** | - | Код возврата (none/high/critical) |  none |
| **--quiet** | -q | Тихий режим (без деталей) |  False |
| **--help** | -h | Показать справку |  - |
---


### Примеры использования


```bash
# Базовое сканирование
cicd-scanner scan .gitlab-ci.yml

# Сканирование с сохранением в JSON
cicd-scanner scan ./ci-configs/ --format json --output audit.json

# Сканирование с возвратом кода 1 при critical
cicd-scanner scan ./ci-configs/ --fail-on critical

# Тихий режим (только ошибки)
cicd-scanner scan ./ci-configs/ --quiet

# Своя директория для отчётов
cicd-scanner scan ./ci-configs/ --output-dir reports/
```


##  Форматы отчётов
---
### Text (консоль + файл)

```
╭──────────────────────────────────────────────────────╮
│ Finding #1                                           │
│ AWS_ACCESS_KEY_ID                                    │
│ File: .gitlab-ci.yml                                 │
│ Line: 9                                              │
│ Value: AKIA***MPLE                                   │
│ Risk Score: 10.0 (critical)                          │
│ Detector: RegexDetector                              │
│ CI System: gitlab                                    │
│ Stage: deploy                                        │
│ Environment: production                              │
│ Hardcoded: Yes                                       │
╰──────────────────────────────────────────────────────╯
```

Файл: Plain text (без ANSI кодов)
```
============================================================
Finding #1
============================================================
  [CRITICAL] AWS_ACCESS_KEY_ID
  File: .gitlab-ci.yml
  Line: 9
  Value: AKIA***MPLE
  Risk Score: 10.0 (critical)
  Detector: RegexDetector
  ...

```
---
### JSON
```
{
  "findings": [
    {
      "file": ".gitlab-ci.yml",
      "line": 9,
      "secret_type": "AWS_ACCESS_KEY_ID",
      "value": "AKIA***MPLE",
      "is_hardcoded": true,
      "context": {
        "ci_system": "gitlab",
        "stage": "deploy",
        "environment": "production",
        "job_name": "deploy_prod"
      },
      "risk_score": 10.0,
      "risk_level": "critical",
      "detector_name": "RegexDetector"
    }
  ],
  "files_scanned": 4,
  "scan_duration_ms": 45.23,
  "summary": {
    "total": 8,
    "hardcoded": 8,
    "critical": 8,
    "high": 0
  }
}
```
---
###  SARIF (для GitHub Security)
```
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CI/CD Secret Scanner",
        "version": "1.0.0"
      }
    },
    "results": [
      {
        "ruleId": "AWS_ACCESS_KEY_ID",
        "level": "error",
        "message": {"text": "Hardcoded AWS_ACCESS_KEY_ID detected"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": ".gitlab-ci.yml"},
            "region": {"startLine": 9}
          }
        }]
      }
    ]
  }]
}
```
```
# Интеграция с GitHub Actions:
# .github/workflows/security-scan.yml
name: Secret Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install scanner
        run: pip install ./cicd-secret-scanner
      
      - name: Run secret scanner
        run: cicd-scanner scan . --format sarif --output results.sarif
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```
---


## Архитектура
---
### Визуализация

```
┌─────────────────────────────────────────────────────────────────┐
│                         CI/CD SECRET SCANNER                    │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   PARSERS   │    │  DETECTORS  │    │  VALIDATORS │          │
│  ├─────────────┤    ├─────────────┤    ├─────────────┤          │
│  │ • GitLab    │    │ • Regex     │    │ • AWS       │          │
│  │ • GitHub    │ →  │ • Entropy   │ →  │ • GitHub    │          │
│  │             │    │ • Context   │    │ • Stripe    │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
│         │                  │                  │                 │
│         └──────────────────┼──────────────────┘                 │
│                            ▼                                    │
│                  ┌─────────────────┐                            │
│                  │  RISK SCORER    │                            │
│                  │  (stage × env)  │                            │
│                  └─────────────────┘                            │
│                            │                                    │
│                            ▼                                    │
│                  ┌─────────────────┐                            │
│                  │   REPORTERS     │                            │
│                  ├─────────────────┤                            │
│                  │ • Console       │                            │
│                  │ • JSON          │                            │
│                  │ • SARIF         │                            │
│                  │ • Text          │                            │
│                  └─────────────────┘                            │
└─────────────────────────────────────────────────────────────────┘

```


### Компоненты
---

| Компонент | Файл | Описание |
|-------------|---------|--------|
| **Parsers** | src/scanner/parsers/ | Парсинг YAML/Groovy в структурированный объект | 
| **Detectors** | src/scanner/detectors/ | Поиск секретов (Regex, Entropy, Contextual) | 
| **Validators** | src/scanner/validators/ | Валидация формата секретов |
| **Risk Scorer** | src/scanner/core/risk_scorer.py | Многофакторная оценка риска | 
| **Reporters** | src/scanner/reporters/ | Вывод результатов (Console, JSON, SARIF, Text) | 
| **Engine** | src/scanner/core/engine.py | Оркестрация пайплайна сканирования |
---


##  Расширение функциональности
### Добавление нового детектора

1. Создайте файл src/scanner/detectors/my_detector.py:

```python
from scanner.detectors.base import DetectorMixin
from scanner.core.models import Finding, PipelineContext

class MyDetector(DetectorMixin):
    """Мой кастомный детектор."""
    
    def get_priority(self) -> int:
        return 4  # Выполняется после остальных
    
    def detect(self, config, all_values, base_findings=None):
        findings = []
        
        for key_path, value, context_dict in all_values:
            if self._is_my_secret(value):
                finding = Finding(
                    file=config.file_path,
                    line=context_dict.get('line', 0),
                    secret_type="MY_SECRET_TYPE",
                    value=value,
                    redacted_value=value[:4] + '***' + value[-4:],
                    is_hardcoded=True,
                    context=PipelineContext(**context_dict),
                    risk_score=7.0,
                    detector_name="MyDetector",
                )
                findings.append(finding)
        
        return findings
    
    def _is_my_secret(self, value: str) -> bool:
        return value.startswith("my_secret_")
```
2. Зарегистрируйте детектор в src/scanner/core/engine.py:

```python
from scanner.detectors.my_detector import MyDetector

class ScannerEngine:
    def __init__(self):
        self.detectors = [
            RegexDetector(),
            EntropyDetector(),
            MyDetector(),
        ]
```

### Добавление нового парсера

1. Создайте файл src/scanner/parsers/my_ci.py:

```python
from scanner.parsers.base import ParserMixin

class MyCIParser(ParserMixin):
    """Парсер для моей CI/CD системы."""
    
    def get_type(self) -> str:
        return "my_ci"
    
    def parse(self, file_path):
        # Твоя логика парсинга
        pass
    
    def get_all_values_with_context(self, config):
        # Извлечение значений с контекстом
        pass
```
2. Зарегистрируйте парсер в src/scanner/core/engine.py:

```python
from scanner.parsers.my_ci import MyCIParser

class ScannerEngine:
    def __init__(self):
        self.parsers = {
            'gitlab': GitLabParser(),
            'github': GitHubParser(),
            'jenkins': JenkinsParser(),
            'my_ci': MyCIParser(), 
        }
```