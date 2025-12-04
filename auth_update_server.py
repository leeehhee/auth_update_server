from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import os
import sqlite3
import bcrypt
import secrets
from datetime import datetime, timedelta

app = FastAPI(title="Auth + Update + BOM Server")

DB_PATH = "auth_update.db"
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ==========================
# DB 연결
# ==========================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ==========================
# DB 테이블 생성
# ==========================
def init_db():
    conn = get_db()
    cur = conn.cursor()

    # 사용자 계정
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        is_active INTEGER NOT NULL DEFAULT 1
    )
    """)

    # 앱 업데이트 정보
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

    # 첨부파일
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

    # =====================
    # 🔥 여기서부터 중요: BOM 시스템
    # =====================

    # 제품
    cur.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT
    )
    """)

    # BOM
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bom_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        spec TEXT,
        length REAL,
        width REAL,
        height REAL,
        material TEXT,
        option TEXT,
        qty INTEGER,
        unit_price REAL,
        FOREIGN KEY(product_id) REFERENCES products(id)
    )
    """)

    # 계정 ↔ 제품 연결
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )
    """)

    conn.commit()
    conn.close()


init_db()

# ==========================================================
# Models
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
    must_update: Optional[bool] = None
    latest_version: Optional[str] = None
    download_url: Optional[str] = None
    release_notes: Optional[str] = None
    message: Optional[str] = None


# ==========================================================
# 인증/유틸 함수
# ==========================================================
def create_session(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    token = secrets.token_hex(32)
    now = datetime.utcnow()
    expires = now + timedelta(days=7)

    cur.execute("""
        INSERT INTO sessions (user_id,token,created_at,expires_at)
        VALUES (?,?,?,?)
    """, (user_id, token, now.isoformat(), expires.isoformat()))
    conn.commit()
    conn.close()
    return token


def get_user_by_token(token: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.*
          FROM sessions s
          JOIN users u ON u.id = s.user_id
         WHERE s.token = ?
           AND s.expires_at > ?
    """, (token, datetime.utcnow().isoformat()))
    user = cur.fetchone()
    conn.close()
    return user


def require_user(token: str):
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(401, "토큰이 유효하지 않습니다.")
    return user


def require_admin(token: str):
    user = require_user(token)
    if user["role"] != "admin":
        raise HTTPException(403, "관리자만 사용 가능")
    return user


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
        return LoginResponse(result="fail", message="계정이 없습니다.")

    if not bcrypt.checkpw(req.password.encode(), user["password_hash"].encode()):
        return LoginResponse(result="fail", message="비밀번호 오류")

    token = create_session(user["id"])

    # 버전 확인
    cur.execute("SELECT * FROM apps WHERE name=?", (req.app_name,))
    app_row = cur.fetchone()
    conn.close()

    must_update = False
    latest = None
    url = None
    notes = None

    if app_row:
        latest = app_row["latest_version"]
        url = app_row["download_url"]
        notes = app_row["release_notes"]

        if req.app_version != latest:
            must_update = bool(app_row["force_update"])

    return LoginResponse(
        result="ok",
        token=token,
        role=user["role"],
        must_update=must_update,
        latest_version=latest,
        download_url=url,
        release_notes=notes
    )


# ==========================================================
# -------------------- 제품 / BOM API -----------------------
# ==========================================================

# ------------------ 1) 제품 생성 (관리자)
@app.post("/api/products/create")
def api_product_create(token: str, name: str, description: str = ""):
    admin = require_admin(token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO products(name,description) VALUES(?,?)", (name, description))
    conn.commit()
    conn.close()
    return {"result": "ok"}


# ------------------ 2) 제품 목록 조회(관리자 전체)
@app.get("/api/products/all")
def api_products_all(token: str):
    admin = require_admin(token)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM products")
    rows = cur.fetchall()
    conn.close()
    return {"products": [dict(r) for r in rows]}


# ------------------ 3) 사용자에게 허용된 제품 목록
@app.get("/api/user/products")
def api_user_products(token: str):
    user = require_user(token)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.name, p.description
          FROM user_products up
          JOIN products p ON p.id = up.product_id
         WHERE up.user_id = ?
    """, (user["id"],))
    rows = cur.fetchall()
    conn.close()

    return {"products": [dict(r) for r in rows]}


# ------------------ 4) BOM 추가 (관리자 전용)
@app.post("/api/product/{pid}/bom/add")
def api_bom_add(
        pid: int,
        token: str,
        name: str,
        spec: str = "",
        length: float = 0,
        width: float = 0,
        height: float = 0,
        material: str = "",
        option: str = "",
        qty: int = 0,
        unit_price: float = 0):
    admin = require_admin(token)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO bom_items(product_id,name,spec,length,width,height,material,option,qty,unit_price)
        VALUES(?,?,?,?,?,?,?,?,?,?)
    """, (pid, name, spec, length, width, height, material, option, qty, unit_price))
    conn.commit()
    conn.close()

    return {"result": "ok"}


# ------------------ 5) 제품 BOM 조회 (사용자 권한 체크)
@app.get("/api/product/{pid}/bom")
def api_product_bom(pid: int, token: str):
    user = require_user(token)

    conn = get_db()
    cur = conn.cursor()

    # 접근권한 검사
    cur.execute("""
        SELECT 1 FROM user_products
         WHERE user_id=? AND product_id=?
    """, (user["id"], pid))
    allow = cur.fetchone()
    if not allow:
        raise HTTPException(403, "이 제품에 대한 접근권한이 없습니다.")

    cur.execute("""
        SELECT name,spec,length,width,height,material,option,qty,unit_price
        FROM bom_items
        WHERE product_id=?
    """, (pid,))
    rows = cur.fetchall()
    conn.close()

    return {"bom": [dict(r) for r in rows]}


# ------------------ 6) 사용자 ↔ 제품 연결 (관리자)
@app.post("/api/user/link_product")
def api_user_link_product(token: str, username: str, product_id: int):
    admin = require_admin(token)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    u = cur.fetchone()
    if not u:
        raise HTTPException(404, "사용자 없음")

    cur.execute("INSERT INTO user_products(user_id,product_id) VALUES(?,?)", (u["id"], product_id))
    conn.commit()
    conn.close()

    return {"result": "ok"}
