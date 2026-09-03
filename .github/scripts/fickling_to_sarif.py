import json
import glob

rules = {
    "fickling-unsafe-pickle": {
        "id": "fickling-unsafe-pickle",
        "name": "fickling-unsafe-pickle",
        "shortDescription": {"text": "Pickle file flagged as likely unsafe by Fickling"},
        "fullDescription": {
            "text": "Fickling performs static opcode-level analysis of pickle "
                    "files and flags structural patterns associated with "
                    "malicious payloads, such as non-standard imports invoked "
                    "during deserialization, regardless of whether the "
                    "specific call is on a known denylist."
        },
        "helpUri": "https://github.com/trailofbits/fickling",
        "properties": {"security-severity": "8.0"},
    }
}
results = []

for path in glob.glob("fickling-reports/*.json"):
    with open(path) as f:
        data = json.load(f)

    severity = data.get("severity", "UNKNOWN")
    if severity in ("LIKELY_UNSAFE", "UNSAFE", "ERROR"):
        analysis = data.get("analysis", "Fickling flagged this pickle file as unsafe.")
        source = data.get("_source_file", path)

        results.append({
            "ruleId": "fickling-unsafe-pickle",
            "level": "error",
            "message": {"text": f"[{severity}] {analysis}"},
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
                "name": "Fickling",
                "informationUri": "https://github.com/trailofbits/fickling",
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }],
}

with open("fickling-results.sarif", "w") as f:
    json.dump(sarif, f, indent=2)

print(f"Converted {len(results)} Fickling finding(s) to SARIF.")
