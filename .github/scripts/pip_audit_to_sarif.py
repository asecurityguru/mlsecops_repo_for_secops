import json

with open("pip-audit-results.json") as f:
    data = json.load(f)

rules = {}
results = []

for dep in data.get("dependencies", []):
    name = dep.get("name", "unknown")
    version = dep.get("version", "unknown")
    for vuln in dep.get("vulns", []):
        vuln_id = vuln.get("id", "UNKNOWN")
        fix_versions = ", ".join(vuln.get("fix_versions", [])) or "no fix available"
        description = vuln.get("description", "No description provided.")

        if vuln_id not in rules:
            rules[vuln_id] = {
                "id": vuln_id,
                "name": vuln_id,
                "shortDescription": {"text": f"{vuln_id} in {name}"},
                "fullDescription": {"text": description[:500]},
                "helpUri": f"https://osv.dev/vulnerability/{vuln_id}",
                "properties": {"security-severity": "7.0"},
            }

        results.append({
            "ruleId": vuln_id,
            "level": "error",
            "message": {
                "text": f"{name}=={version} is affected by {vuln_id}. "
                        f"Fix versions: {fix_versions}."
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "pyproject.toml"},
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
                "name": "pip-audit",
                "informationUri": "https://github.com/pypa/pip-audit",
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }],
}

with open("pip-audit-results.sarif", "w") as f:
    json.dump(sarif, f, indent=2)

print(f"Converted {len(results)} finding(s) to SARIF.")
