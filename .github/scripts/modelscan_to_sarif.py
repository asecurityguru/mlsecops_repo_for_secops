import json

with open("modelscan-results.json") as f:
    data = json.load(f)

severity_map = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

rules = {}
results = []

for issue in data.get("issues", []):
    rule_id = f"modelscan-{issue.get('module', 'unknown')}-{issue.get('operator', 'unknown')}"
    description = issue.get("description", "Unsafe operator detected in model file.")
    source = issue.get("source", "unknown")
    severity = issue.get("severity", "MEDIUM")

    if rule_id not in rules:
        rules[rule_id] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": description[:120]},
            "fullDescription": {"text": description},
            "helpUri": "https://github.com/protectai/modelscan",
            "properties": {"security-severity": "9.0" if severity == "CRITICAL" else "6.0"},
        }

    results.append({
        "ruleId": rule_id,
        "level": severity_map.get(severity, "warning"),
        "message": {"text": description},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": source},
                "region": {"startLine": 1}
            }
        }]
    })

sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "ModelScan",
                "informationUri": "https://github.com/protectai/modelscan",
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }],
}

with open("modelscan-results.sarif", "w") as f:
    json.dump(sarif, f, indent=2)

print(f"Converted {len(results)} ModelScan finding(s) to SARIF.")
