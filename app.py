from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import os
import secrets
import time

app = Flask(__name__)

# ── 修复3：安全密钥 ─────────────────────────────────────────────────
# 从环境变量读取密钥，不存在则随机生成（避免硬编码弱密钥）
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── 修复5：Session 安全配置 ────────────────────────────────────────
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # 禁止 JS 读取 Cookie，防 XSS 窃取
    SESSION_COOKIE_SAMESITE="Lax",      # 防 CSRF 跨站请求
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),  # Session 2小时过期
    SESSION_COOKIE_NAME="session_id",   # 避免使用默认的 "session" 名称
)

# ── 修复1：密码以哈希存储（不再存明文） ────────────────────────────
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password_hash": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# ── 修复7：登录失败记录（防暴力破解） ──────────────────────────────
# 格式: { "ip:username": {"count": N, "time": timestamp} }
_login_attempts: dict = {}
_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_SECONDS = 300  # 5分钟锁定


def _cleanup_attempts():
    """清理过期的失败记录（5分钟 TTL）。"""
    now = time.time()
    for key in list(_login_attempts.keys()):
        if now - _login_attempts[key]["time"] > _LOCKOUT_SECONDS:
            del _login_attempts[key]


# ── 修复8：安全响应头 ───────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # HSTS 仅在生产环境启用
    if not app.debug:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response


def _safe_user_info(username: str) -> dict | None:
    """返回不包含密码哈希的用户信息字典。"""
    user = USERS.get(username)
    if not user:
        return None
    return {k: v for k, v in user.items() if k != "password_hash"}


# ── 路由 ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    username = session.get("username")
    user_info = _safe_user_info(username) if username else None
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"
        lock_key = f"{client_ip}:{username}"

        # 修复7：防暴力破解检查
        _cleanup_attempts()
        if lock_key in _login_attempts:
            if _login_attempts[lock_key]["count"] >= _MAX_LOGIN_ATTEMPTS:
                return render_template(
                    "login.html",
                    error="登录失败次数过多，请5分钟后再试",
                )

        # 修复1：用 check_password_hash 比对（防时序攻击）
        user = USERS.get(username)
        if user and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["username"] = username
            # 登录成功，清除该用户的失败记录
            _login_attempts.pop(lock_key, None)
            return redirect(url_for("index"))
        else:
            # 记录失败次数
            if lock_key in _login_attempts:
                _login_attempts[lock_key]["count"] += 1
                _login_attempts[lock_key]["time"] = time.time()
            else:
                _login_attempts[lock_key] = {"count": 1, "time": time.time()}

            remaining = _MAX_LOGIN_ATTEMPTS - _login_attempts[lock_key]["count"]
            error_msg = "用户名或密码错误"
            if remaining > 0 and remaining < _MAX_LOGIN_ATTEMPTS:
                error_msg += f"（还剩 {remaining} 次尝试机会）"
            return render_template("login.html", error=error_msg)

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()  # fix: 用 clear() 替代 pop 单个 key，更彻底
    return redirect(url_for("index"))


# ── 启动 ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # 修复4：debug 由环境变量控制，生产环境关闭
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, host="0.0.0.0", port=5000)
