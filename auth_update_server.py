from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import bcrypt
import secrets
import os
from datetime import datetime, timedelta

# ==========================================================
# FastAPI 앱
# ==========================================================
app = FastAPI(
    title="Auth + Update + BOM Server",
    version="0.1.0",
    description="통합 계정 + 업데이트 + 제품 + BOM + 파일 + 로그 서버"
)

DB_PATH = "auth_update.db"
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ==========================================================
# DB 연결 / 초기화
# ==========================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # 사용자
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            company TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        )
        """
    )

    # 앱 정보 (업데이트용)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            latest_version TEXT NOT NULL,
            download_url TEXT NOT NULL,
            release_notes TEXT,
            force_update INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    # 세션 정보
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    # 제품
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT,
            description TEXT
        )
        """
    )

    # 사용자 ↔ 제품 연결
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
        """
    )

    # BOM
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS bom (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            name TEXT,
            spec TEXT,
            length REAL,
            width REAL,
            height REAL,
            material TEXT,
            option TEXT,
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
        """
    )

    # 로그 (클라이언트 동작 기록)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            app_name TEXT,
            action TEXT,
            detail TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    # 파일 관리
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            description TEXT,
            uploaded_by INTEGER,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(uploaded_by) REFERENCES users(id)
        )
        """
    )

    conn.commit()
    conn.close()


init_db()

# ==========================================================
# 유틸 함수
# ==========================================================
def create_session(user_id: int) -> str:
    """세션 생성하고 토큰 반환"""
    conn = get_db()
    cur = conn.cursor()
    token = secrets.token_hex(32)

    now = datetime.utcnow()
    exp = now + timedelta(days=7)

    cur.execute(
        """
        INSERT INTO sessions(user_id, token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, token, now.isoformat(), exp.isoformat()),
    )

    conn.commit()
    conn.close()
    return token


def get_user_by_token(token: str):
    """세션 토큰으로 유저 조회"""
    if not token:
        return None
    conn = get_db()
    cur = conn.cursor()

    now = datetime.utcnow().isoformat()
    cur.execute(
        """
        SELECT u.*
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > ?
        """,
        (token, now),
    )

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
        raise HTTPException(403, "관리자만 접근 가능합니다.")
    return user


def log_event_db(user_id, app_name, action, detail):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO logs(user_id, app_name, action, detail, created_at)
        VALUES(?,?,?,?,?)
        """,
        (user_id, app_name, action, detail, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


# ==========================================================
# Pydantic Models
# ==========================================================
class LoginRequest(BaseModel):
    app_name: str
    app_version: str
    username: str
    password: str


class LoginResponse(BaseModel):
    result: str
    token: Optional[str] = None
    role: Optional[str] = None
    latest_version: Optional[str] = None
    download_url: Optional[str] = None
    must_update: Optional[bool] = False
    release_notes: Optional[str] = None
    message: Optional[str] = None


class UserCreateRequest(BaseModel):
    token: str
    username: str
    password: str
    company: Optional[str] = None
    role: str = "user"


class UserListRequest(BaseModel):
    token: str


class UserDeleteRequest(BaseModel):
    token: str
    username: str


class ProductCreateRequest(BaseModel):
    token: str
    name: str
    category: Optional[str] = None
    description: Optional[str] = None


class LinkProductRequest(BaseModel):
    token: str
    username: str
    product_id: int


class BOMItem(BaseModel):
    name: str
    spec: str
    length: float
    width: float
    height: float
    material: str
    option: Optional[str] = None


class BOMAddRequest(BaseModel):
    token: str
    items: List[BOMItem]


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


class FileListRequest(BaseModel):
    token: str


class FileDeleteRequest(BaseModel):
    token: str
    file_id: int


# ==========================================================
# LOGIN
# ==========================================================
@app.post("/api/login", response_model=LoginResponse)
def login(req: LoginRequest):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? AND is_active=1", (req.username,))
    user = cur.fetchone()

    if not user:
        # 유저 없음
        log_event_db(None, req.app_name, "login_fail", "no_user")
        return LoginResponse(result="fail", message="계정이 없습니다.")

    if not bcrypt.checkpw(req.password.encode(), user["password_hash"].encode()):
        # 비밀번호 틀림
        log_event_db(user["id"], req.app_name, "login_fail", "wrong_password")
        return LoginResponse(result="fail", message="비밀번호가 올바르지 않습니다.")

    token = create_session(user["id"])
    log_event_db(user["id"], req.app_name, "login_success", f"version={req.app_version}")

    # 앱 버전 정보 확인
    cur.execute("SELECT * FROM apps WHERE name=?", (req.app_name,))
    app_row = cur.fetchone()
    conn.close()

    latest_version = None
    download_url = None
    release_notes = None
    must_update = False

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
        latest_version=latest_version,
        download_url=download_url,
        must_update=must_update,
        release_notes=release_notes,
    )


# ==========================================================
# UPDATE 체크
# ==========================================================
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
        release_notes=app_row["release_notes"],
    )


# ==========================================================
# LOG 이벤트 수신
# ==========================================================
@app.post("/api/log_event")
def log_event(req: LogEventRequest):
    user_id = None
    if req.token:
        user = get_user_by_token(req.token)
        if user:
            user_id = user["id"]
    log_event_db(user_id, req.app_name, req.action, req.detail or "")
    return {"result": "ok"}


# ==========================================================
# ADMIN - 최초 관리자 생성
# ==========================================================
@app.post("/api/admin/create")
def api_admin_create(username: str, password: str):
    """최초 1회 관리자 계정 생성용 (Swagger에서만 사용 권장)"""
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO users(username,password_hash,role,is_active)
        VALUES(?, ?, 'admin',1)
        """,
        (username, hashed),
    )
    conn.commit()
    conn.close()
    return {"result": "admin created 👍"}


# ==========================================================
# USER 관리 (리스트 / 생성 / 삭제)
# ==========================================================
@app.post("/api/users/list")
def api_users_list(req: UserListRequest):
    admin = require_admin(req.token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username, role, is_active, company FROM users ORDER BY username")
    rows = cur.fetchall()
    conn.close()
    users = [
        {
            "username": r["username"],
            "role": r["role"],
            "is_active": bool(r["is_active"]),
            "company": r["company"] or "",
        }
        for r in rows
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

    cur.execute(
        """
        INSERT INTO users(username,password_hash,role,company,is_active)
        VALUES(?,?,?,?,1)
        """,
        (req.username, hashed, req.role, req.company),
    )
    conn.commit()
    conn.close()
    return {"result": "ok"}


@app.post("/api/users/delete")
def api_user_delete(req: UserDeleteRequest):
    admin = require_admin(req.token)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=?", (req.username,))
    conn.commit()
    conn.close()
    return {"result": "ok"}


# ==========================================================
# PRODUCT 생성 / 조회
# ==========================================================
@app.post("/api/products/create")
def create_product(req: ProductCreateRequest):
    admin = require_admin(req.token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO products(name,category,description)
        VALUES(?,?,?)
        """,
        (req.name, req.category, req.description),
    )
    conn.commit()
    pid = cur.lastrowid
    conn.close()
    return {"result": "ok", "product_id": pid}


@app.get("/api/products/all")
def get_products(token: str):
    user = require_user(token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM products")
    rows = cur.fetchall()
    conn.close()
    return {"products": [dict(r) for r in rows]}


# ==========================================================
# 계정 ↔ 제품 연결
# ==========================================================
@app.post("/api/user/link_product")
def api_link_product(req: LinkProductRequest):
    admin = require_admin(req.token)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username=?", (req.username,))
    u = cur.fetchone()
    if not u:
        conn.close()
        raise HTTPException(404, "user not found")

    cur.execute(
        """
        INSERT INTO user_products(user_id, product_id)
        VALUES(?,?)
        """,
        (u["id"], req.product_id),
    )

    conn.commit()
    conn.close()
    return {"result": "ok"}


# ==========================================================
# 사용자 제품 목록 조회
# ==========================================================
@app.get("/api/user/products")
def api_user_products(token: str):
    user = require_user(token)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT p.*
        FROM user_products up
        JOIN products p ON p.id = up.product_id
        WHERE up.user_id = ?
        """,
        (user["id"],),
    )
    rows = cur.fetchall()
    conn.close()
    return {"products": [dict(r) for r in rows]}


# ==========================================================
# BOM 등록 / 조회
# ==========================================================
@app.post("/api/product/{pid}/bom/add")
def api_bom_add(pid: int, req: BOMAddRequest):
    admin = require_admin(req.token)

    conn = get_db()
    cur = conn.cursor()

    # 기존 BOM 삭제 후 다시 등록하고 싶다면 아래 두 줄 주석 해제
    # cur.execute("DELETE FROM bom WHERE product_id=?", (pid,))

    for item in req.items:
        cur.execute(
            """
            INSERT INTO bom(product_id,name,spec,length,width,height,material,option)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                pid,
                item.name,
                item.spec,
                item.length,
                item.width,
                item.height,
                item.material,
                item.option,
            ),
        )
    conn.commit()
    conn.close()
    return {"result": "ok"}


@app.get("/api/product/{pid}/bom")
def api_bom_get(pid: int, token: str):
    user = require_user(token)

    conn = get_db()
    cur = conn.cursor()

    # 권한 체크: 해당 유저가 이 제품을 가지고 있는지 확인
    cur.execute(
        """
        SELECT 1
        FROM user_products
        WHERE user_id=? AND product_id=?
        """,
        (user["id"], pid),
    )
    if not cur.fetchone():
        conn.close()
        raise HTTPException(403, "해당 제품에 대한 권한이 없습니다.")

    cur.execute("SELECT * FROM bom WHERE product_id=?", (pid,))
    rows = cur.fetchall()
    conn.close()
    return {"bom": [dict(r) for r in rows]}


# ==========================================================
# 파일 관리 API (선택 기능이지만 이미 클라이언트에서 사용)
# ==========================================================
@app.post("/api/files/list")
def api_files_list(req: FileListRequest):
    user = require_user(req.token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT f.id, f.filename, f.description, f.uploaded_at,
               u.username AS uploaded_by
        FROM files f
        LEFT JOIN users u ON u.id = f.uploaded_by
        ORDER BY f.id DESC
        """
    )
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
    file: UploadFile = File(...),
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
    cur.execute(
        """
        INSERT INTO files(filename,stored_path,description,uploaded_by,uploaded_at)
        VALUES(?,?,?,?,?)
        """,
        (safe_name, stored_path, description, admin["id"], datetime.utcnow().isoformat()),
    )
    conn.commit()
    file_id = cur.lastrowid
    conn.close()
    return {"result": "ok", "file_id": file_id}


@app.post("/api/files/update")
async def api_files_update(
    file_id: int = Form(...),
    token: str = Form(...),
    description: str = Form(""),
    file: UploadFile = File(...),
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

    cur.execute(
        """
        UPDATE files
           SET filename=?, stored_path=?, description=?, uploaded_by=?, uploaded_at=?
         WHERE id=?
        """,
        (safe_name, stored_path, description, admin["id"], datetime.utcnow().isoformat(), file_id),
    )
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
