from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import os
import sqlite3
import bcrypt
import secrets
from datetime import datetime, timedelta

app = FastAPI(title="Auth + Update + Log + File Server")

DB_PATH = "auth_update.db"
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # 사용자
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        is_active INTEGER NOT NULL DEFAULT 1
    )
    """)

    # 앱 버전
    cur.execute("""
    CREATE TABLE IF NOT EXISTS apps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        latest_version TEXT NOT NULL,
        download_url TEXT NOT NULL,
        release_notes TEXT,
        force_update INTEGER NOT NULL DEFAULT 0
    )
    """)

    # 세션
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # 로그
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        app_name TEXT,
        action TEXT,
        detail TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # 첨부 파일
    cur.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        description TEXT,
        uploaded_by INTEGER,
        uploaded_at TEXT NOT NULL,
        FOREIGN KEY(uploaded_by) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()


init_db()


# ---------- 모델 ----------

class LoginRequest(BaseModel):
    app_name: str
    app_version: str
    username: str
    password: str


class LoginResponse(BaseModel):
    result: str
    token: Optional[str] = None
    role: Optional[str] = None
    must_update: Optional[bool] = None
    latest_version: Optional[str] = None
    download_url: Optional[str] = None
    release_notes: Optional[str] = None
    message: Optional[str] = None


class LogEventRequest(BaseModel):
    token: Optional[str] = None
    app_name: str
    action: str
    detail: Optional[str] = None


class UpdateInfoResponse(BaseModel):
    latest_version: str
    must_update: bool
    download_url: str
    release_notes: Optional[str] = None


class UserListRequest(BaseModel):
    token: str


class UserCreateRequest(BaseModel):
    token: str
    username: str
    password: str
    role: str = "user"


class UserDeleteRequest(BaseModel):
    token: str
    username: str


class FileListRequest(BaseModel):
    token: str


class FileDeleteRequest(BaseModel):
    token: str
    file_id: int


# ---------- 공통 함수 ----------

def create_session(user_id: int) -> str:
    conn = get_db()
    cur = conn.cursor()
    token = secrets.token_hex(32)
    now = datetime.utcnow()
    expires = now + timedelta(days=7)
    cur.execute("""
        INSERT INTO sessions (user_id, token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    """, (user_id, token, now.isoformat(), expires.isoformat()))
    conn.commit()
    conn.close()
    return token


def get_user_by_token(token: str):
    if not token:
        return None
    conn = get_db()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute("""
        SELECT u.*
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > ?
    """, (token, now))
    row = cur.fetchone()
    conn.close()
    return row


def require_user(token: str):
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(401, "토큰이 유효하지 않습니다.")
    return user


def require_admin(token: str):
    user = require_user(token)
    if user["role"] != "admin":
        raise HTTPException(403, "관리자만 사용할 수 있습니다.")
    return user


def log_event(user_id, app_name, action, detail):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs(user_id, app_name, action, detail, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, app_name, action, detail, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


# ---------- 기본 API (로그인 / 업데이트 / 로그) ----------

@app.post("/api/login", response_model=LoginResponse)
def login(req: LoginRequest):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE username=? AND is_active=1",
                (req.username,))
    user = cur.fetchone()

    if not user:
        log_event(None, req.app_name, "login_fail", "no_user")
        return LoginResponse(result="fail", message="계정이 없습니다.")

    if not bcrypt.checkpw(req.password.encode(),
                          user["password_hash"].encode()):
        log_event(user["id"], req.app_name, "login_fail", "wrong_password")
        return LoginResponse(result="fail", message="비밀번호가 올바르지 않습니다.")

    token = create_session(user["id"])
    log_event(user["id"], req.app_name, "login_success",
              f"version={req.app_version}")

    cur.execute("SELECT * FROM apps WHERE name=?", (req.app_name,))
    app_row = cur.fetchone()
    conn.close()

    must_update = False
    latest_version = None
    download_url = None
    release_notes = None

    if app_row:
        latest_version = app_row["latest_version"]
        download_url = app_row["download_url"]
        release_notes = app_row["release_notes"]
        if req.app_version != latest_version:
            must_update = bool(app_row["force_update"])

    return LoginResponse(
        result="ok",
        token=token,
        role=user["role"],
        must_update=must_update,
        latest_version=latest_version,
        download_url=download_url,
        release_notes=release_notes
    )


@app.get("/api/check_update", response_model=UpdateInfoResponse)
def check_update(app_name: str, version: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM apps WHERE name=?", (app_name,))
    app_row = cur.fetchone()
    conn.close()

    if not app_row:
        raise HTTPException(404, "앱 정보가 없습니다.")

    latest_version = app_row["latest_version"]
    must_update = (version != latest_version) and bool(app_row["force_update"])

    return UpdateInfoResponse(
        latest_version=latest_version,
        must_update=must_update,
        download_url=app_row["download_url"],
        release_notes=app_row["release_notes"]
    )


@app.post("/api/log_event")
def log_event_endpoint(req: LogEventRequest):
    user_id = None
    if req.token:
        user = get_user_by_token(req.token)
        if user:
            user_id = user["id"]
    log_event(user_id, req.app_name, req.action, req.detail)
    return {"result": "ok"}


# ---------- 관리자 계정 최초 생성 ----------

@app.post("/api/admin/create")
def create_admin(username: str, password: str):
    conn = get_db()
    cur = conn.cursor()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    cur.execute("""
        INSERT INTO users(username,password_hash,role)
        VALUES(?, ?, 'admin')
    """, (username, hashed))
    conn.commit()
    conn.close()
    return {"result": "admin created 👍"}


# ---------- 사용자(타업체 계정) 관리 ----------

@app.post("/api/users/list")
def api_users_list(req: UserListRequest):
    admin = require_admin(req.token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username, role, is_active FROM users ORDER BY username")
    rows = cur.fetchall()
    conn.close()
    users = [
        {
            "username": r["username"],
            "role": r["role"],
            "is_active": bool(r["is_active"])
        } for r in rows
    ]
    return {"users": users}


@app.post("/api/users/create")
def api_user_create(req: UserCreateRequest):
    admin = require_admin(req.token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (req.username,))
    if cur.fetchone():
        conn.close()
        raise HTTPException(400, "이미 존재하는 계정입니다.")
    hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    cur.execute("""
        INSERT INTO users(username,password_hash,role,is_active)
        VALUES(?,?,?,1)
    """, (req.username, hashed, req.role))
    conn.commit()
    conn.close()
    return {"result": "ok"}


@app.post("/api/users/delete")
def api_user_delete(req: UserDeleteRequest):
    admin = require_admin(req.token)
    if admin["username"] == req.username:
        raise HTTPException(400, "자기 자신의 계정은 삭제할 수 없습니다.")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=?", (req.username,))
    conn.commit()
    conn.close()
    return {"result": "ok"}


# ---------- 파일(첨부) 관리 ----------

@app.post("/api/files/list")
def api_files_list(req: FileListRequest):
    user = require_user(req.token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT f.id, f.filename, f.description, f.uploaded_at,
               u.username AS uploaded_by
        FROM files f
        LEFT JOIN users u ON u.id = f.uploaded_by
        ORDER BY f.id DESC
    """)
    rows = cur.fetchall()
    conn.close()
    files = [
        {
            "id": r["id"],
            "filename": r["filename"],
            "description": r["description"],
            "uploaded_at": r["uploaded_at"],
            "uploaded_by": r["uploaded_by"],
        }
        for r in rows
    ]
    return {"files": files}


@app.post("/api/files/delete")
def api_files_delete(req: FileDeleteRequest):
    admin = require_admin(req.token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT stored_path FROM files WHERE id=?", (req.file_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "파일을 찾을 수 없습니다.")
    stored_path = row["stored_path"]
    try:
        if os.path.exists(stored_path):
            os.remove(stored_path)
    except Exception:
        pass
    cur.execute("DELETE FROM files WHERE id=?", (req.file_id,))
    conn.commit()
    conn.close()
    return {"result": "ok"}


@app.post("/api/files/upload")
async def api_files_upload(
    token: str = Form(...),
    description: str = Form(""),
    file: UploadFile = File(...)
):
    admin = require_admin(token)
    safe_name = os.path.basename(file.filename)
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    stored_name = f"{ts}_{safe_name}"
    stored_path = os.path.join(UPLOAD_DIR, stored_name)

    with open(stored_path, "wb") as f:
        f.write(await file.read())

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO files(filename,stored_path,description,uploaded_by,uploaded_at)
        VALUES(?,?,?,?,?)
    """, (safe_name, stored_path, description, admin["id"], datetime.utcnow().isoformat()))
    conn.commit()
    file_id = cur.lastrowid
    conn.close()
    return {"result": "ok", "file_id": file_id}


@app.post("/api/files/update")
async def api_files_update(
    file_id: int = Form(...),
    token: str = Form(...),
    description: str = Form(""),
    file: UploadFile = File(...)
):
    admin = require_admin(token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT stored_path FROM files WHERE id=?", (file_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "파일을 찾을 수 없습니다.")
    old_path = row["stored_path"]
    try:
        if os.path.exists(old_path):
            os.remove(old_path)
    except Exception:
        pass

    safe_name = os.path.basename(file.filename)
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    stored_name = f"{ts}_{safe_name}"
    stored_path = os.path.join(UPLOAD_DIR, stored_name)
    with open(stored_path, "wb") as f:
        f.write(await file.read())

    cur.execute("""
        UPDATE files
           SET filename=?, stored_path=?, description=?, uploaded_by=?, uploaded_at=?
         WHERE id=?
    """, (safe_name, stored_path, description, admin["id"], datetime.utcnow().isoformat(), file_id))
    conn.commit()
    conn.close()
    return {"result": "ok"}


@app.get("/api/files/download/{file_id}")
def api_files_download(file_id: int, token: str):
    user = require_user(token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT filename, stored_path FROM files WHERE id=?", (file_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "파일을 찾을 수 없습니다.")

    return FileResponse(row["stored_path"], filename=row["filename"])
