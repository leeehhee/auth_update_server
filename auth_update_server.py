from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import bcrypt
import secrets
import os
from datetime import datetime, timedelta

app = FastAPI(
    title="Auth + Update + BOM Server",
    version="0.1.0",
    description="통합 계정 + 업데이트 + 제품 + BOM + 파일 + 로그 서버"
)

DB_PATH = "auth_update.db"
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ==========================================================
# DB 연결
# ==========================================================
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
            company TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    """)

    # 앱 정보
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

    # 세션 정보
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

    # 제품 테이블
    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT,
            description TEXT
        )
    """)

    # 사용자 ↔ 제품 연결
    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """)

    # BOM 테이블
    cur.execute("""
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
    """)

    conn.commit()
    conn.close()

init_db()

# ==========================================================
# Utility
# ==========================================================
def create_session(user_id: int) -> str:
    conn = get_db()
    cur = conn.cursor()
    token = secrets.token_hex(32)

    now = datetime.utcnow()
    exp = now + timedelta(days=7)

    cur.execute("""
        INSERT INTO sessions(user_id, token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    """, (user_id, token, now.isoformat(), exp.isoformat()))

    conn.commit()
    conn.close()
    return token


def get_user_by_token(token: str):
    conn = get_db()
    cur = conn.cursor()

    now = datetime.utcnow().isoformat()
    cur.execute("""
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > ?
    """, (token, now))

    row = cur.fetchone()
    conn.close()
    return row


def require_user(token: str):
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(401, "Invalid token")
    return user


def require_admin(token: str):
    user = require_user(token)
    if user["role"] != "admin":
        raise HTTPException(403, "관리자만 접근 가능합니다.")
    return user

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

class UserCreateRequest(BaseModel):
    token: str
    username: str
    password: str
    company: Optional[str] = None
    role: str = "user"

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

# ==========================================================
# LOGIN
# ==========================================================
@app.post("/api/login", response_model=LoginResponse)
def login(req: LoginRequest):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (req.username,))
    user = cur.fetchone()

    if not user:
        return LoginResponse(result="fail", message="no user")

    if not bcrypt.checkpw(req.password.encode(), user["password_hash"].encode()):
        return LoginResponse(result="fail", message="wrong password")

    token = create_session(user["id"])

    return LoginResponse(
        result="ok",
        token=token,
        role=user["role"]
    )


# ==========================================================
# ADMIN - 최초 관리자 생성
# ==========================================================
@app.post("/api/admin/create")
def api_admin_create(username: str, password: str):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO users(username,password_hash,role,is_active)
        VALUES(?, ?, 'admin',1)
    """, (username, hashed))
    conn.commit()
    conn.close()
    return {"result": "admin created 👍"}


# ==========================================================
# USER 생성
# ==========================================================
@app.post("/api/users/create")
def api_user_create(req: UserCreateRequest):
    admin = require_admin(req.token)

    conn = get_db()
    cur = conn.cursor()

    hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()

    cur.execute("""
        INSERT INTO users(username,password_hash,role,company,is_active)
        VALUES(?,?,?,?,1)
    """, (req.username, hashed, req.role, req.company))
    conn.commit()
    conn.close()
    return {"result": "ok"}


# ==========================================================
# PRODUCT 생성
# ==========================================================
@app.post("/api/products/create")
def create_product(req: ProductCreateRequest):
    admin = require_admin(req.token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO products(name,category,description)
        VALUES(?,?,?)
    """, (req.name, req.category, req.description))
    conn.commit()
    pid = cur.lastrowid
    conn.close()
    return {"result": "ok", "product_id": pid}


# ==========================================================
# 모든 제품 조회
# ==========================================================
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
        raise HTTPException(404, "user not found")

    cur.execute("""
        INSERT INTO user_products(user_id, product_id)
        VALUES(?,?)
    """, (u["id"], req.product_id))

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
    cur.execute("""
        SELECT p.*
        FROM user_products up
        JOIN products p ON p.id = up.product_id
        WHERE up.user_id = ?
    """, (user["id"],))
    rows = cur.fetchall()
    conn.close()
    return {"products": [dict(r) for r in rows]}


# ==========================================================
# BOM 등록
# ==========================================================
@app.post("/api/product/{pid}/bom/add")
def api_bom_add(pid: int, req: BOMAddRequest):
    admin = require_admin(req.token)

    conn = get_db()
    cur = conn.cursor()

    for item in req.items:
        cur.execute("""
            INSERT INTO bom(product_id,name,spec,length,width,height,material,option)
            VALUES(?,?,?,?,?,?,?,?)
        """, (
            pid,
            item.name,
            item.spec,
            item.length,
            item.width,
            item.height,
            item.material,
            item.option
        ))
    conn.commit()
    conn.close()
    return {"result": "ok"}


# ==========================================================
# BOM 조회
# ==========================================================
@app.get("/api/product/{pid}/bom")
def api_bom_get(pid: int, token: str):
    user = require_user(token)

    # 권한 체크
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT 1
        FROM user_products
        WHERE user_id=? AND product_id=?
    """, (user["id"], pid))

    if not cur.fetchone():
        raise HTTPException(403, "해당 제품 권한 없음")

    cur.execute("SELECT * FROM bom WHERE product_id=?", (pid,))
    rows = cur.fetchall()
    conn.close()
    return {"bom": [dict(r) for r in rows]}
