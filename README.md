# MLSecOps Demo Repo

This repo is a hands-on demo for teaching **MLSecOps** — securing machine
learning / LLM applications inside a CI/CD pipeline. It's built on top of
[LLMGoat](https://github.com/SECFORCE/LLMGoat), a deliberately vulnerable
LLM application based on the OWASP Top 10 for LLM Applications, with a few
extra files added specifically to demo model-artifact scanning.

It exists to answer one question: **what does a security pipeline
look like once "the app" includes a trained model, not just source code?**

## What this project actually is

A small Flask web app (`llmgoat`) that runs a local LLM and exposes ten
deliberately vulnerable challenges, one per OWASP LLM Top 10 category. The
app itself isn't the point of this course — it's realistic bait. The point
is the `.github/` folder: four GitHub Actions workflows that scan this repo
with six different security tools, covering source code, dependencies, and
the model/cache files a normal web app would never have.

## What makes this an ML/AI project (not just a web app)


| Where | Why it's ML-specific |
|---|---|
| `llmgoat/llm/manager.py` | Loads and runs a local LLM (`llama-cpp-python`) — downloads a `.gguf` model file and serves inference from it. This is the actual "ML" in the app. |
| `pyproject.toml` dependencies | `llama-cpp-python`, `torch`, `transformers`, `sentence-transformers` — an ML/LLM stack, not a typical web app's dependency list. |
| `llmgoat/challenges/` | Ten challenge modules, each mapping to one OWASP LLM Top 10 risk (prompt injection, data/model poisoning, vector/embedding weaknesses, excessive agency, etc.) — risks that only exist because the app is LLM-driven. |
| `models/cache.pkl` and `models/cache_denylisted.pkl` | Model/cache artifacts in pickle format — the file type this whole course is built around, since a trained model or cache file can execute code on load in a way a normal config file never could. |
| `pickle_payload_module/`, `build_malicious_pickle.py`, `utils/cache_loader.py` | Not part of the original LLMGoat — added to this fork purely to give the model-scanning tools (ModelScan, Fickling) something realistic to catch, since LLMGoat's native model format (GGUF) has no pickle-style code-execution surface. |
| `.semgrep/ml-security-rules.yml` | Custom static-analysis rules written for ML-specific antipatterns (e.g. unsafe `torch.load()`), not generic web app bugs. |

Everything else in the repo — `Dockerfile`, `compose.*.yaml`, the Flask
routes, the templates — is standard web app plumbing you'd find in any
containerized Python service. It's the six items above that make this
specifically an ML security demo rather than a generic DevSecOps one.

## Running it locally

```bash
docker compose -f compose.local.yaml up llmgoat-cpu
```

The app listens on `http://localhost:5000`.

## The CI/CD security pipeline

Four workflows in `.github/workflows/` scan this repo on every push and pull
request. Each one is explained in its own file, in `docs/`:

- [`docs/security-sast.md`](docs/security-sast.md) — CodeQL + Bandit (source code)
- [`docs/sca-scan.md`](docs/sca-scan.md) — Trivy + pip-audit (dependencies + image)
- [`docs/model-scan.md`](docs/model-scan.md) — ModelScan + Fickling (model & cache files)
- [`docs/docker.md`](docs/docker.md) — image build & publish

All findings land in this repo's **Security → Code scanning** tab.

## Disclaimer

This application is intentionally vulnerable. Don't deploy it to a publicly
reachable host or use real credentials with it — it exists for training and
demonstration purposes only.
