"""
Importable module containing the function that the malicious pickle's
__reduce__ will call at load time. Pickle requires __reduce__ targets to
be importable by dotted path, which is itself part of the real-world
attack surface: an attacker only needs ANY importable callable already
present in the target environment (os.system, subprocess.Popen, etc.) -
they do not need to ship their own module like we are doing here for
this teaching demo.
"""
import os


def write_marker(path, message):
    with open(path, "w") as f:
        f.write(message)
    return True
