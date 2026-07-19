from flask import Flask, render_template, request, redirect, session, url_for
import time

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# 明文密码存储在字典中
USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# ── 防暴力破解（保持） ────────────────────────────────────────────────
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


# ── 路由 ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"
        lock_key = f"{client_ip}:{username}"

        # 防暴力破解检查（保持）
        _cleanup_attempts()
        if lock_key in _login_attempts:
            if _login_attempts[lock_key]["count"] >= _MAX_LOGIN_ATTEMPTS:
                return render_template(
                    "login.html",
                    error="登录失败次数过多，请5分钟后再试",
                )

        # 直接用 == 比对明文密码
        if username in USERS and USERS[username]["password"] == password:
            session["username"] = username
            # 登录成功，清除该用户的失败记录
            _login_attempts.pop(lock_key, None)
            user_info = USERS[username]
            return render_template("index.html", user=user_info)
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
    session.pop("username", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
