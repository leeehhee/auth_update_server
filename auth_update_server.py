from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import sqlite3
import bcrypt
import secrets
from datetime import datetime, timedelta

# ===============================
# 🌐 FastAPI 서버 생성
# ===============================
app = FastAPI(title="Auth + Update + Log Server")

# ===============================
# 📁 데이터베이스 파일 경로
# ===============================
DB_PATH = "auth_update.db"


# ===============================
# DB 연결 함수
# ===============================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ===============================
# 최초 실행 시 DB 테이블 자동 생성
# ===============================
def init_db():
    conn = get_db()
    cur = conn.cursor()

    # 사용자 테이블
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        is_active INTEGER NOT NULL DEFAULT 1
    )
    """)

    # 앱 버전 관리 테이블
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

    # 로그인 세션
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

    # 로그 기록
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

    conn.commit()
    conn.close()


# DB 초기화 실행
init_db()


# ===============================
# 📦 API 데이터 구조 (모델)
# ===============================

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


# ===============================
# ⭐ 세션 토큰 발급
# ===============================

def create_session(user_id: int):
    conn = get_db()
    cur = conn.cursor()

    token = secrets.token_hex(32)
    now = datetime.utcnow()
    expires = now + timedelta(days=7)  # 7일 후 만료

    cur.execute("""
        INSERT INTO sessions(user_id, token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    """, (user_id, token, now.isoformat(), expires.isoformat()))

    conn.commit()
    conn.close()
    return token


# ===============================
# ⭐ 토큰으로 사용자 찾기 (로그 기록용)
# ===============================
def get_user_by_token(token: str):
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


# ===============================
# ⭐ 로그 저장
# ===============================

def log_event(user_id, app_name, action, detail):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs(user_id, app_name, action, detail, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, app_name, action, detail, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


# ====================================================
# 🔐 로그인 API
# ====================================================
@app.post("/api/login", response_model=LoginResponse)
def login(req: LoginRequest):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE username=? AND is_active=1",
                (req.username,))
    user = cur.fetchone()

    # 계정 없을 때
    if not user:
        log_event(None, req.app_name, "login_fail", "no_user")
        return LoginResponse(result="fail", message="❌ 계정이 없습니다")

    # 비밀번호 검증
    if not bcrypt.checkpw(req.password.encode(),
                          user["password_hash"].encode()):
        log_event(user["id"], req.app_name, "login_fail", "wrong_password")
        return LoginResponse(result="fail", message="❌ 비밀번호 오류")

    # 세션 발급
    token = create_session(user["id"])
    log_event(user["id"], req.app_name, "login_success", f"v={req.app_version}")

    # 앱 업데이트 정보 조회
    cur.execute("SELECT * FROM apps WHERE name=?", (req.app_name,))
    app_row = cur.fetchone()
    conn.close()

    must_update = False
    latest_version = None
    download_url = None
    release_notes = None

    # 앱 등록되어있으면 최신버전 비교
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


# ====================================================
# 🔄 업데이트 정보 조회 API
# ====================================================
@app.get("/api/check_update", response_model=UpdateInfoResponse)
def check_update(app_name: str, version: str):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM apps WHERE name=?", (app_name,))
    app_row = cur.fetchone()
    conn.close()

    if not app_row:
        raise HTTPException(404, "앱 등록 없음")

    latest_version = app_row["latest_version"]
    must_update = (version != latest_version) and bool(app_row["force_update"])

    return UpdateInfoResponse(
        latest_version=latest_version,
        must_update=must_update,
        download_url=app_row["download_url"],
        release_notes=app_row["release_notes"]
    )


# ====================================================
# 📝 로그 기록 API
# ====================================================
@app.post("/api/log_event")
def api_log(req: LogEventRequest):
    uid = None
    if req.token:
        user = get_user_by_token(req.token)
        if user:
            uid = user["id"]

    log_event(uid, req.app_name, req.action, req.detail)
    return {"result": "ok"}


# ====================================================
# ⭐ 관리자 계정 생성 (최초 1회)
# ====================================================
@app.post("/api/admin/create")
def create_admin(username: str, password: str):
    conn = get_db()
    cur = conn.cursor()

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    cur.execute(
        "INSERT INTO users(username,password_hash,role) VALUES(?,?, 'admin')",
        (username, hashed)
    )

    conn.commit()
    conn.close()
    return {"result": "admin created 👍"}
