# Vuln-MLMini (intentionally vulnerable)
A tiny, intentionally vulnerable Python/Flask app inspired by a *very* small subset of MLflow ideas:
- experiments
- runs
- params / metrics
- artifacts

⚠️ **Do not deploy this on the internet.** It is intentionally insecure for local security practice.

## Quickstart
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open: http://127.0.0.1:5000

## Features (what it pretends to do)
- Create experiments + runs
- Log parameters/metrics
- Upload artifacts
- Download "remote artifact" by URL
- "Model registry" that can load a saved model

## Intentional vulnerabilities (high level)
1) **SSRF**: `/api/fetch?url=...` fetches arbitrary URLs with no allowlist.
2) **Zip Slip / Path Traversal on extraction**: uploading a `.zip` to `/api/artifacts/upload_zip/<run_id>` uses `ZipFile.extractall(...)` unsafely.
3) **Unsafe deserialization**: `/api/models/load` loads a Python pickle from a user-controlled path.
4) **IDOR / no auth**: all run IDs are guessable and there is no auth.

## Storage layout
- `data/app.db` : SQLite DB
- `data/artifacts/<run_id>/...` : artifacts extracted/written here
- `data/models/` : saved models

## Notes
- The app uses a naive DB schema and minimal validation on purpose.
- The UI is intentionally simple; most interaction is via the HTML forms on `/`.
