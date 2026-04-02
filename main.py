"""
main.py — QCP Export & Import Web App
======================================
FastAPI backend that proxies all ALM API calls.
Browser never talks to ALM directly — all auth + file handling is server-side.

Run:  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

import asyncio
import json
import logging
import os
import tempfile
import threading
import uuid
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
from typing import Optional

import requests
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv()

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent          # always points to the folder containing main.py

app = FastAPI(title="QCP Export & Import Tool", version="1.0.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOGIN_PATH      = "/qcbin/rest/oauth2/login"
REQUEST_TIMEOUT = 120
LOG_FILE        = Path(__file__).resolve().parent / "qcp_web.log"

DB_TYPES = {"MS SQL Server": "2", "Oracle": "3"}

# ---------------------------------------------------------------------------
# File-based logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("qcp_web")

# ---------------------------------------------------------------------------
# Per-session log queues  (session_id → threading.Queue)
# Each browser tab/request gets its own queue for SSE log delivery.
# ---------------------------------------------------------------------------
_queues: dict[str, Queue] = {}
_queues_lock = threading.Lock()

# Temporary files waiting to be downloaded: token → {path, filename}
_download_store: dict[str, dict] = {}
_download_lock  = threading.Lock()


def _get_queue(session_id: str) -> Queue:
    with _queues_lock:
        if session_id not in _queues:
            _queues[session_id] = Queue()
        return _queues[session_id]


def _cleanup_queue(session_id: str) -> None:
    with _queues_lock:
        _queues.pop(session_id, None)


def _push(session_id: str, **kwargs) -> None:
    _get_queue(session_id).put({
        **kwargs,
        "time": datetime.now().strftime("%H:%M:%S"),
    })


def push_log(session_id: str, level: str, msg: str) -> None:
    logger.log(getattr(logging, level, logging.INFO), "[%s] %s", session_id[:8], msg)
    _push(session_id, type="log", level=level, msg=msg)


def push_done(session_id: str, **data) -> None:
    _push(session_id, type="done", **data)


def push_error(session_id: str, msg: str) -> None:
    logger.error("[%s] %s", session_id[:8], msg)
    _push(session_id, type="error", msg=msg)

# ---------------------------------------------------------------------------
# ALM HTTP helpers
# ---------------------------------------------------------------------------

def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=2, backoff_factor=1,
        status_forcelist={502, 503, 504},
        allowed_methods={"GET", "POST"},
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    session.headers.update({"Accept": "application/json"})
    return session


def _alm_login(session: requests.Session, base_url: str,
               client_id: str, secret: str, sid: str) -> None:
    url = base_url.rstrip("/") + LOGIN_PATH
    push_log(sid, "INFO", f"Authenticating → {url}")
    resp = session.post(
        url,
        json={"clientId": client_id, "secret": secret},
        headers={"Content-Type": "application/json"},
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code == 401:
        raise RuntimeError("Login rejected (401) — check Client ID and API Key Secret.")
    if resp.status_code == 403:
        raise RuntimeError("Login forbidden (403) — account may be locked.")
    if not resp.ok:
        raise RuntimeError(f"Login failed (HTTP {resp.status_code}): {resp.text[:300]}")
    xsrf = session.cookies.get("XSRF-TOKEN", "")
    if xsrf:
        session.headers.update({"X-XSRF-TOKEN": xsrf})
    push_log(sid, "INFO", "Authentication successful")


def _alm_error_detail(resp: requests.Response) -> str:
    try:
        jb  = resp.json()
        qce = jb.get("QCRestException", {})
        return (qce.get("Title") or qce.get("Id") or
                jb.get("message") or jb.get("error_description") or
                resp.text[:300])
    except Exception:
        return resp.text[:300]

# ---------------------------------------------------------------------------
# Export worker  (runs in a background thread)
# ---------------------------------------------------------------------------

def _export_worker(base_url: str, domain: str, project: str,
                   client_id: str, secret: str, session_id: str) -> None:
    tmp_path: Optional[str] = None
    try:
        session = _build_session()
        _alm_login(session, base_url, client_id, secret, session_id)

        url = (f"{base_url.rstrip('/')}/qcbin/v2/sa/api/domains/"
               f"{domain}/projects/{project}/export")
        push_log(session_id, "INFO", f"GET {url}")
        push_log(session_id, "INFO", "Requesting export from ALM…")

        with session.get(url, stream=True, timeout=REQUEST_TIMEOUT) as resp:
            if resp.status_code == 401:
                _alm_login(session, base_url, client_id, secret, session_id)
                resp = session.get(url, stream=True, timeout=REQUEST_TIMEOUT)

            if not resp.ok:
                raise RuntimeError(
                    f"Export failed (HTTP {resp.status_code}): "
                    f"{_alm_error_detail(resp)}"
                )

            push_log(session_id, "INFO",
                     f"Connected — Content-Type: {resp.headers.get('Content-Type', '?')}")

            total      = int(resp.headers.get("content-length", 0))
            downloaded = 0

            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".qcp")
            tmp_path = tmp.name

            for chunk in resp.iter_content(chunk_size=65_536):
                if chunk:
                    tmp.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = int(downloaded / total * 100)
                        push_log(session_id, "INFO", f"Downloading… {pct}%")
                    else:
                        push_log(session_id, "INFO",
                                 f"Downloading… {downloaded // 1024} KB received")
            tmp.close()

        size_kb  = Path(tmp_path).stat().st_size / 1024
        filename = f"{project}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.qcp"

        token = str(uuid.uuid4())
        with _download_lock:
            _download_store[token] = {"path": tmp_path, "filename": filename}

        push_log(session_id, "INFO",
                 f"Export complete — {size_kb:.1f} KB  →  {filename}")
        push_done(session_id, token=token, filename=filename, size_kb=round(size_kb, 1))

    except Exception as exc:
        push_error(session_id, str(exc))
        if tmp_path and Path(tmp_path).exists():
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

# ---------------------------------------------------------------------------
# Import worker  (runs in a background thread)
# ---------------------------------------------------------------------------

def _import_worker(base_url: str, domain: str, client_id: str, secret: str,
                   session_id: str, qcp_path: str, project_name: str,
                   db_server: str, db_type: str, tablespace: str,
                   temp_tablespace: str, skip_lab: bool) -> None:
    try:
        session = _build_session()
        _alm_login(session, base_url, client_id, secret, session_id)

        url = (f"{base_url.rstrip('/')}/qcbin/v2/sa/api/domains/"
               f"{domain}/projects/import")
        push_log(session_id, "INFO", f"POST {url}")

        qcp = Path(qcp_path)
        size_mb = qcp.stat().st_size / (1024 * 1024)
        push_log(session_id, "INFO",
                 f"Uploading {qcp.name}  ({size_mb:.2f} MB) — please wait…")

        form_fields: dict = {
            "name":            (None, project_name),
            "db-server-name":  (None, db_server),
            "db-type":         (None, db_type),
        }
        if tablespace:
            form_fields["tablespace"]      = (None, tablespace)
        if temp_tablespace:
            form_fields["temp-tablespace"] = (None, temp_tablespace)
        if skip_lab:
            form_fields["skip-lab-projects-validation"] = (None, "true")

        with open(qcp_path, "rb") as f:
            form_fields["file-name"] = (qcp.name, f, "application/octet-stream")
            resp = session.post(
                url,
                files=form_fields,
                headers={"Accept": "application/json"},
                timeout=REQUEST_TIMEOUT,
            )

        if not resp.ok:
            raise RuntimeError(
                f"Import failed (HTTP {resp.status_code}): "
                f"{_alm_error_detail(resp)}"
            )

        data    = resp.json()
        project = data.get("project", data)
        push_log(session_id, "INFO",
                 f"Import successful — project '{project.get('name')}' "
                 f"created (id: {project.get('id')})")
        push_done(session_id, project=project)

    except Exception as exc:
        push_error(session_id, str(exc))
    finally:
        try:
            os.unlink(qcp_path)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/api/events")
async def sse_events(session_id: str):
    """
    Server-Sent Events stream for a specific session.
    The browser opens this before submitting the operation form,
    then receives log messages + final done/error event.
    """
    q    = _get_queue(session_id)
    loop = asyncio.get_event_loop()

    async def generate():
        try:
            while True:
                try:
                    item = await loop.run_in_executor(
                        None, lambda: q.get(timeout=30)
                    )
                    yield f"data: {json.dumps(item)}\n\n"
                    if item.get("type") in ("done", "error"):
                        break
                except Empty:
                    # Keep-alive ping every 30 s so the connection stays open
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        finally:
            _cleanup_queue(session_id)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",        # disable Nginx buffering
            "Connection":       "keep-alive",
        },
    )


@app.post("/api/export")
async def api_export(
    base_url:      str = Form(...),
    domain:        str = Form(...),
    project:       str = Form(...),
    client_id:     str = Form(...),
    client_secret: str = Form(...),
    session_id:    str = Form(...),
):
    threading.Thread(
        target=_export_worker,
        args=(base_url, domain, project, client_id, client_secret, session_id),
        daemon=True,
    ).start()
    return {"status": "started", "session_id": session_id}


@app.get("/api/download/{token}")
async def api_download(token: str, background_tasks: BackgroundTasks):
    with _download_lock:
        info = _download_store.pop(token, None)
    if not info:
        raise HTTPException(status_code=404, detail="Download link expired or not found.")

    path     = info["path"]
    filename = info["filename"]

    # Delete temp file after response is sent
    background_tasks.add_task(lambda: os.unlink(path) if Path(path).exists() else None)

    return FileResponse(
        path=path,
        filename=filename,
        media_type="application/octet-stream",
    )


@app.post("/api/import")
async def api_import(
    base_url:        str        = Form(...),
    domain:          str        = Form(...),
    client_id:       str        = Form(...),
    client_secret:   str        = Form(...),
    session_id:      str        = Form(...),
    project_name:    str        = Form(...),
    db_server:       str        = Form(...),
    db_type:         str        = Form(...),
    tablespace:      str        = Form("QC_ADMIN"),
    temp_tablespace: str        = Form("TEMP"),
    skip_lab:        str        = Form("false"),
    qcp_file:        UploadFile = File(...),
):
    # Save uploaded QCP to temp file (import worker reads it from there)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".qcp")
    tmp.write(await qcp_file.read())
    tmp.close()

    threading.Thread(
        target=_import_worker,
        args=(
            base_url, domain, client_id, client_secret, session_id,
            tmp.name, project_name, db_server, db_type,
            tablespace, temp_tablespace, skip_lab == "true",
        ),
        daemon=True,
    ).start()
    return {"status": "started", "session_id": session_id}
