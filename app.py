from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
import time

import re

app = Flask(__name__)
app.secret_key = "dev-key-2025"


# ── 输入过滤 ─────────────────────────────────────────────────────────

def sanitize(value: str, max_len: int = 64) -> str:
    """清洗用户输入：去空白、去特殊字符、限制长度。"""
    if not value:
        return ""
    # 去首尾空白
    value = value.strip()
    # 只保留字母、数字、中文、@、.、-、_  （拒绝 SQL 特殊字符）
    value = re.sub(r"[^\w一-鿿@.\- ]", "", value)
    # 限制长度
    return value[:max_len]


def sanitize_password(value: str) -> str:
    """密码只去空白和限制长度，保留更多字符。"""
    if not value:
        return ""
    value = value.strip()
    # 拒绝明显恶意的字符（SQL/命令注入）
    value = re.sub(r"[';\"\\\-]|--", "", value)
    return value[:128]


# ── 数据库初始化 ──────────────────────────────────────────────────────

def init_db():
    """初始化数据库，创建 users 表并插入默认用户。"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    conn.commit()

    # 插入默认用户（INSERT OR IGNORE 防止重复插入）
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')"
    )
    conn.commit()
    conn.close()


init_db()


# ── 防暴力破解 ────────────────────────────────────────────────────────

_login_attempts: dict = {}
_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_SECONDS = 300


def _cleanup_attempts():
    now = time.time()
    for key in list(_login_attempts.keys()):
        if now - _login_attempts[key]["time"] > _LOCKOUT_SECONDS:
            del _login_attempts[key]


# ── 路由 ──────────────────────────────────────────────────────────────


@app.route("/")
def index():
    username = session.get("username")
    user_info = get_user(username) if username else None
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize(request.form.get("username", ""))
        password = sanitize_password(request.form.get("password", ""))
        client_ip = request.remote_addr or "unknown"
        lock_key = f"{client_ip}:{username}"

        _cleanup_attempts()
        if lock_key in _login_attempts and _login_attempts[lock_key]["count"] >= _MAX_LOGIN_ATTEMPTS:
            return render_template("login.html", error="登录失败次数过多，请5分钟后再试")

        # 使用参数化查询，防 SQL 注入
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cur.fetchone()
        conn.close()

        if user:
            session["username"] = user["username"]
            _login_attempts.pop(lock_key, None)
            return redirect(url_for("index"))
        else:
            if lock_key in _login_attempts:
                _login_attempts[lock_key]["count"] += 1
                _login_attempts[lock_key]["time"] = time.time()
            else:
                _login_attempts[lock_key] = {"count": 1, "time": time.time()}

            remaining = _MAX_LOGIN_ATTEMPTS - _login_attempts[lock_key]["count"]
            error_msg = "用户名或密码错误"
            if 0 < remaining < _MAX_LOGIN_ATTEMPTS:
                error_msg += f"（还剩 {remaining} 次尝试机会）"
            return render_template("login.html", error=error_msg)

    # 获取 URL 参数中的成功消息
    success = sanitize(request.args.get("success", ""))
    return render_template("login.html", success=success)


# ── 用户查询辅助 ─────────────────────────────────────────────────────

def get_user(username):
    """根据用户名查询用户信息。"""
    if not username:
        return None
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = sanitize(request.form.get("username", ""))
        password = sanitize_password(request.form.get("password", ""))
        email = sanitize(request.form.get("email", ""))
        phone = sanitize(request.form.get("phone", ""))

        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空")

        # 使用参数化查询插入，防 SQL 注入
        conn = sqlite3.connect("data/users.db")
        try:
            sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
            print(f"[SQL] {sql}")
            conn.execute(sql, (username, password, email, phone))
            conn.commit()
            conn.close()
            return redirect(url_for("login", success="注册成功，请登录"))
        except Exception as e:
            conn.close()
            return render_template("register.html", error=f"注册失败: {e}")

    return render_template("register.html")


@app.route("/search")
def search():
    """搜索用户（★★★ 使用 f-string 拼接 SQL，存在注入漏洞 ★★★）"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    keyword = sanitize(request.args.get("keyword", ""))

    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row

    if not keyword:
        return render_template("index.html", user=get_user(username), search_results=[], search_keyword="")

    # 使用参数化查询，防 SQL 注入
    sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
    like_pattern = f"%{keyword}%"
    print(f"[SQL] {sql} (keyword=%{keyword}%)")

    results = []
    try:
        cur = conn.execute(sql, (like_pattern, like_pattern))
        rows = cur.fetchall()
        results = [dict(r) for r in rows]
    except Exception as e:
        print(f"[SQL ERROR] {e}")

    conn.close()

    user_info = get_user(username)

    return render_template("index.html", user=user_info, search_results=results, search_keyword=keyword)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
