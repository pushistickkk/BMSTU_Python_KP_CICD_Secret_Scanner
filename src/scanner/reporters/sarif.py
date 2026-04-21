"""SARIF Reporter — вывод в формате для GitHub Security."""

import json
from pathlib import Path
from scanner.core.models import ScanResult, RiskLevel
from scanner.reporters.base import ReporterMixin


class SARIFReporter(ReporterMixin):
    """Генерирует отчёт в формате SARIF 2.1.0."""
    
    def report(self, result: ScanResult, output_path: Path | str | None = None) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CI/CD Secret Scanner",
                        "version": "1.0.0",
                        "informationUri": "cicd-secret-scanner",
                        "rules": self._generate_rules(),
                    }
                },
                "results": self._generate_results(result),
            }]
        }
        
        output = json.dumps(sarif, indent=2, ensure_ascii=False)
        
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output)
        
        return output
    
    def _generate_rules(self):
        return [
            {
                "id": "AWS_CREDENTIALS",
                "name": "AWS Credentials",
                "shortDescription": {"text": "Hardcoded AWS credentials detected"},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "GITHUB_TOKEN",
                "name": "GitHub Token",
                "shortDescription": {"text": "Hardcoded GitHub token detected"},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "DATABASE_URL",
                "name": "Database Connection String",
                "shortDescription": {"text": "Hardcoded database credentials"},
                "defaultConfiguration": {"level": "error"},
            },
        ]
    
    def _generate_results(self, result: ScanResult):
        results = []
        for finding in result.findings:
            level = "error" if finding.risk_level == RiskLevel.CRITICAL else "warning"
            
            results.append({
                "ruleId": finding.secret_type,
                "level": level,
                "message": {"text": f"Hardcoded {finding.secret_type} detected"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        "region": {"startLine": finding.line or 1},
                    }
                }],
                "properties": {
                    "riskScore": finding.risk_score,
                    "detector": finding.detector_name,
                    "ciSystem": finding.context.ci_system,
                },
            })
        return results