import os
import sqlite3
import time
import uuid
import pickle
from pathlib import Path
from zipfile import ZipFile

import requests
from flask import Flask, g, jsonify, redirect, render_template, request, send_from_directory, url_for

APP_ROOT = Path(__file__).resolve().parent
DATA_DIR = APP_ROOT / "data"
DB_PATH = DATA_DIR / "app.db"
ARTIFACTS_DIR = DATA_DIR / "artifacts"
MODELS_DIR = DATA_DIR / "models"

DATA_DIR.mkdir(exist_ok=True)
ARTIFACTS_DIR.mkdir(exist_ok=True)
MODELS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB (still unsafe - just for convenience)

# -----------------------------
# DB helpers
# -----------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS experiments (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS runs (
          id TEXT PRIMARY KEY,
          experiment_id TEXT NOT NULL,
          name TEXT,
          status TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS params (
          run_id TEXT NOT NULL,
          k TEXT NOT NULL,
          v TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS metrics (
          run_id TEXT NOT NULL,
          k TEXT NOT NULL,
          v REAL NOT NULL,
          ts INTEGER NOT NULL
        );
        """
    )
    db.commit()

@app.before_request
def _ensure_db():
    init_db()

# -----------------------------
# Basic pages
# -----------------------------
@app.get("/")
def index():
    db = get_db()
    exps = db.execute("SELECT * FROM experiments ORDER BY created_at DESC").fetchall()
    runs = db.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT 50").fetchall()
    return render_template("index.html", experiments=exps, runs=runs)

@app.get("/runs/<run_id>")
def run_detail(run_id: str):
    db = get_db()
    run = db.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not run:
        return ("Run not found", 404)

    params = db.execute("SELECT k, v FROM params WHERE run_id = ?", (run_id,)).fetchall()
    metrics = db.execute("SELECT k, v, ts FROM metrics WHERE run_id = ? ORDER BY ts DESC", (run_id,)).fetchall()

    run_art_dir = ARTIFACTS_DIR / run_id
    artifacts = []
    if run_art_dir.exists():
        for p in sorted(run_art_dir.rglob("*")):
            if p.is_file():
                artifacts.append(str(p.relative_to(run_art_dir)).replace("\\", "/"))
    return render_template("run.html", run=run, params=params, metrics=metrics, artifacts=artifacts)

# -----------------------------
# API: experiments & runs
# -----------------------------
@app.post("/api/experiments")
def create_experiment():
    name = request.form.get("name") or request.json.get("name")
    exp_id = str(uuid.uuid4())
    db = get_db()
    db.execute("INSERT INTO experiments (id, name, created_at) VALUES (?, ?, ?)", (exp_id, name, int(time.time())))
    db.commit()
    return redirect(url_for("index"))

@app.post("/api/runs")
def create_run():
    experiment_id = request.form.get("experiment_id") or request.json.get("experiment_id")
    run_name = request.form.get("name") or (request.json.get("name") if request.is_json else None)
    run_id = str(uuid.uuid4())
    db = get_db()
    db.execute(
        "INSERT INTO runs (id, experiment_id, name, status, created_at) VALUES (?, ?, ?, ?, ?)",
        (run_id, experiment_id, run_name, "RUNNING", int(time.time())),
    )
    db.commit()
    return redirect(url_for("run_detail", run_id=run_id))

@app.post("/api/runs/<run_id>/param")
def log_param(run_id: str):
    k = request.form.get("k") or request.json.get("k")
    v = request.form.get("v") or request.json.get("v")
    db = get_db()
    db.execute("INSERT INTO params (run_id, k, v) VALUES (?, ?, ?)", (run_id, k, v))
    db.commit()
    return redirect(url_for("run_detail", run_id=run_id))

@app.post("/api/runs/<run_id>/metric")
def log_metric(run_id: str):
    k = request.form.get("k") or request.json.get("k")
    v = float(request.form.get("v") or request.json.get("v"))
    db = get_db()
    db.execute("INSERT INTO metrics (run_id, k, v, ts) VALUES (?, ?, ?, ?)", (run_id, k, v, int(time.time())))
    db.commit()
    return redirect(url_for("run_detail", run_id=run_id))

@app.post("/api/runs/<run_id>/finish")
def finish_run(run_id: str):
    db = get_db()
    db.execute("UPDATE runs SET status = ? WHERE id = ?", ("FINISHED", run_id))
    db.commit()
    return redirect(url_for("run_detail", run_id=run_id))

# -----------------------------
# API: artifacts (intentionally vulnerable)
# -----------------------------
@app.post("/api/artifacts/upload_file/<run_id>")
def upload_file(run_id: str):
    # Intentionally naive: file name is trusted; no auth; no content checks
    f = request.files.get("file")
    if not f:
        return ("missing file", 400)
    run_dir = ARTIFACTS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    dest = run_dir / (f.filename or "uploaded.bin")
    dest.parent.mkdir(parents=True, exist_ok=True)
    f.save(dest)
    return redirect(url_for("run_detail", run_id=run_id))

@app.post("/api/artifacts/upload_zip/<run_id>")
def upload_zip(run_id: str):
    """
    Intentional vuln: Zip Slip / path traversal.
    Uses ZipFile.extractall without validating member paths.
    """
    zf = request.files.get("zip")
    if not zf:
        return ("missing zip", 400)

    run_dir = ARTIFACTS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tmp_path = run_dir / "upload.zip"
    zf.save(tmp_path)

    with ZipFile(tmp_path, "r") as z:
        # VULN: extractall can write outside run_dir if zip contains ../ or absolute paths
        z.extractall(run_dir)

    return redirect(url_for("run_detail", run_id=run_id))

@app.get("/api/artifacts/<run_id>/<path:artifact_path>")
def download_artifact(run_id: str, artifact_path: str):
    # Intentionally naive: no allowlist, no auth, no safe path checks
    run_dir = ARTIFACTS_DIR / run_id
    return send_from_directory(run_dir, artifact_path, as_attachment=True)

@app.get("/api/fetch")
def fetch_remote_artifact():
    """
    Intentional vuln: SSRF
    Fetches an arbitrary URL and stores it under a run artifacts directory.
    """
    url = request.args.get("url", "")
    run_id = request.args.get("run_id", "")
    name = request.args.get("name", "remote.bin")

    if not run_id:
        return ("run_id required", 400)

    run_dir = ARTIFACTS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # VULN: no allowlist/blocklist, no DNS rebinding checks, no timeouts, etc.
    r = requests.get(url, timeout=10)
    dest = run_dir / name
    dest.write_bytes(r.content)
    return jsonify({"saved_to": f"data/artifacts/{run_id}/{name}", "bytes": len(r.content)})

# -----------------------------
# API: "model registry" (intentionally vulnerable)
# -----------------------------
@app.post("/api/models/save")
def save_model():
    """
    Saves a model as a pickle.
    Not a vuln by itself, but combined with load() it becomes dangerous.
    """
    model_name = request.form.get("name", "demo-model.pkl")
    payload = request.form.get("payload", "just a demo model object")
    model_path = MODELS_DIR / model_name
    with open(model_path, "wb") as f:
        pickle.dump({"payload": payload, "saved_at": time.time()}, f)
    return jsonify({"saved": str(model_path)})

@app.get("/api/models/load")
def load_model():
    """
    Intentional vuln: unsafe deserialization (pickle).
    Loads a pickle from a user-controlled file path.
    """
    path = request.args.get("path", "")
    # VULN: user-controlled path, and pickle.load on attacker-controlled content
    with open(path, "rb") as f:
        obj = pickle.load(f)
    return jsonify({"loaded_type": str(type(obj)), "loaded": repr(obj)[:500]})

@app.post("/api/webhook/test")
def webhook_test():
    """
    Intentional vuln: SSRF
    User supplies an arbitrary URL and we request it server-side.
    """
    url = request.form.get("url") or (request.json.get("url") if request.is_json else "")
    method = (request.form.get("method") or (request.json.get("method") if request.is_json else "GET")).upper()
    body = request.form.get("body") or (request.json.get("body") if request.is_json else "")
    headers_raw = request.form.get("headers") or (request.json.get("headers") if request.is_json else "{}")

    try:
        import json
        headers = json.loads(headers_raw) if headers_raw else {}
    except Exception:
        headers = {}

    # VULN: no URL validation, allowlist, IP range block, redirect control, etc.
    resp = requests.request(method, url, data=body.encode("utf-8"), headers=headers, timeout=10, allow_redirects=True)

    return jsonify({
        "status_code": resp.status_code,
        "final_url": str(resp.url),
        "response_headers": dict(resp.headers),
        "body_preview": resp.text[:2000],
    })

@app.post("/api/runs/<run_id>/load_evaluator")
def load_evaluator(run_id: str):
    """
    Intentional vuln: arbitrary code execution via dynamic import.
    Loads and executes attacker-controlled Python code.
    """
    plugin_path = request.form.get("path") or (
        request.json.get("path") if request.is_json else ""
    )
    entrypoint = request.form.get("entrypoint", "evaluate")

    if not plugin_path:
        return ("path required", 400)

    # VULN: attacker controls filesystem path
    import importlib.util

    spec = importlib.util.spec_from_file_location("user_plugin", plugin_path)
    module = importlib.util.module_from_spec(spec)

    # 🚨 RCE happens here
    spec.loader.exec_module(module)

    if not hasattr(module, entrypoint):
        return ("entrypoint not found", 400)

    fn = getattr(module, entrypoint)

    # Execute user code
    result = fn(run_id=run_id)

    return jsonify({
        "status": "evaluator executed",
        "result": result
    })

# -----------------------------
# Run the app
# -----------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
