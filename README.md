# Model scan teaching addition for LLMGoat

These files are NOT part of the original SECFORCE/LLMGoat project. They
were added to this fork specifically to teach model artifact scanning
(ModelScan, Fickling) in the MLSecOps course, since LLMGoat natively uses
the GGUF model format, which has no pickle-style code execution surface
to demonstrate.

## What's in here

- `models/cache.pkl` - a deliberately malicious pickle file. Loading it
  with `pickle.load()` executes a payload via `__reduce__`. The payload
  is harmless: it writes a marker text file to prove execution occurred.
  No network access, no real attacker code, no persistence beyond the demo.

- `utils/cache_loader.py` - a realistic (and intentionally vulnerable)
  loader module showing how an application might load this kind of
  cache file via `pickle.load()`. This is the file Bandit will flag.

- `pickle_payload_module/payload_funcs.py` - an importable module
  containing the harmless function the pickle payload calls. Pickle
  requires `__reduce__` targets to be importable by dotted path; in a
  real attack, the attacker targets a callable ALREADY present in the
  victim's environment (os.system, subprocess.Popen, etc.) rather than
  shipping their own module like this demo does for auditability.

- `build_malicious_pickle.py` - the script that builds `models/cache.pkl`.
  Re-run it if you need to regenerate the artifact.

## How to install into your LLMGoat fork

1. Copy `models/cache.pkl` into your repo's `models/` folder (create it
   if it doesn't exist).
2. Copy `utils/cache_loader.py` into `llmgoat/utils/cache_loader.py`.
3. Copy `pickle_payload_module/` into your repo root, OR inline the
   `write_marker` function directly into an existing utils module if you
   prefer not to add a new top-level package - just update the import in
   `cache_loader.py` to match wherever you place it.
4. Optionally wire `load_embeddings_cache()` into your app's startup path
   so it's clear this is "real" loaded code, not dead code - though for
   scanning purposes (ModelScan/Fickling/Bandit) this isn't required;
   static scanners inspect the file and the call site regardless of
   whether it runs at startup.

## Verifying it works

```bash
cd your-llmgoat-fork
python3 -c "
from llmgoat.utils.cache_loader import load_embeddings_cache
load_embeddings_cache()
"
cat PWNED_BY_PICKLE.txt   # should now exist
```

Clean up the marker file after testing - it's not meant to be committed.
