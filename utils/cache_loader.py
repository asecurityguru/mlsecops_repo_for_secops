"""
cache_loader.py

Loads a cached embeddings/tokenizer-state file at application startup.

SECURITY NOTE FOR STUDENTS: this module is intentionally vulnerable. It
was added to this fork of LLMGoat to teach model artifact scanning - it
is NOT part of the original SECFORCE/LLMGoat project.

The vulnerability: pickle.load() executes arbitrary code embedded in the
file via __reduce__, as a normal part of deserialization. Loading an
untrusted or tampered cache.pkl can result in full code execution with
the privileges of this process - this is exactly the class of risk
Bandit flags with its B301 rule, and the class of risk ModelScan /
Fickling are designed to catch by inspecting the file BEFORE it is ever
loaded.

The safe alternative is to avoid pickle entirely for this kind of data -
use json for plain data, or safetensors for tensor/embedding data, both
of which cannot embed executable code.
"""
import pickle
import os

CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "models", "cache.pkl"
)


def load_embeddings_cache():
    """
    Loads the embeddings cache from disk.

    VULNERABLE: uses pickle.load() on a file that may come from an
    untrusted source (e.g. downloaded alongside a model, or written by
    a previous, possibly compromised, pipeline step).
    """
    if not os.path.exists(CACHE_PATH):
        return None

    with open(CACHE_PATH, "rb") as f:
        cache = pickle.load(f)  # noqa: S301 - intentionally vulnerable for this demo

    return cache


if __name__ == "__main__":
    result = load_embeddings_cache()
    print("Cache loaded:", result)
