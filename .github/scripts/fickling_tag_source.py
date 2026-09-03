import json
import sys

src, path = sys.argv[1], sys.argv[2]
try:
    with open(path) as fh:
        data = json.load(fh)
except FileNotFoundError:
    data = {"severity": "ERROR", "analysis": "Fickling produced no output for this file."}
data["_source_file"] = src
with open(path, "w") as fh:
    json.dump(data, fh)
