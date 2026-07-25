from flask import Flask, render_template, render_template_string, request, redirect, session, url_for, abort
import sqlite3
import os
import time
import re
import secrets
import hmac
from datetime import timedelta
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = "dev-key-2025"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# ── CSRF 防护 ─────────────────────────────────────────────────────────
# 默认 SameSite=Strict，阻止跨站请求携带 Cookie
app.config.update(
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

ALLOWED_ORIGINS = {"http://127.0.0.1:5000", "http://localhost:5000"}


def check_csrf():
    """验证 CSRF Token 和 Referer。"""
    # 检查 Referer
    referer = request.headers.get("Referer", "")
    if referer:
        from urllib.parse import urlparse
        parsed = urlparse(referer)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in ALLOWED_ORIGINS:
            abort(403, "CSRF: 非法的请求来源")

    # 验证 CSRF Token
    token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token")
    if not token or not session_token:
        abort(403, "CSRF: 缺少 Token")
    if not hmac.compare_digest(token, session_token):
        abort(403, "CSRF: Token 不匹配")


def generate_csrf_token():
    """生成并存储 CSRF Token 到 session。"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf_token


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
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)
    conn.commit()

    # 为旧表添加 balance 字段（如果不存在）
    try:
        conn.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # 字段已存在

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

# ── 注册频率限制 ────────────────────────────────────────────────────
_reg_attempts: dict = {}
_MAX_REG_PER_HOUR = 10  # 每小时最多注册10个账号


def _cleanup_attempts():
    now = time.time()
    for key in list(_login_attempts.keys()):
        if now - _login_attempts[key]["time"] > _LOCKOUT_SECONDS:
            del _login_attempts[key]


def _cleanup_reg_attempts():
    now = time.time()
    for key in list(_reg_attempts.keys()):
        if now - _reg_attempts[key]["time"] > 3600:
            del _reg_attempts[key]


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

        # 修复批量注册漏洞：IP频率限制
        client_ip = request.remote_addr or "unknown"
        _cleanup_reg_attempts()
        if client_ip in _reg_attempts and _reg_attempts[client_ip]["count"] >= _MAX_REG_PER_HOUR:
            return render_template("register.html", error="注册过于频繁，请稍后再试")
        if client_ip in _reg_attempts:
            _reg_attempts[client_ip]["count"] += 1
        else:
            _reg_attempts[client_ip] = {"count": 1, "time": time.time()}

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


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """用户头像上传（只允许图片类文件）。"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件")

        # 检查文件后缀是否允许
        allowed_extensions = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico"}
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in allowed_extensions:
            return render_template("upload.html", error="只允许上传图片文件（jpg、jpeg、png、gif、bmp、webp、svg、ico）")

        # 检查 MIME 类型是否以 image/ 开头
        mime = file.content_type or ""
        if not mime.startswith("image/"):
            return render_template("upload.html", error="文件类型必须是图片")

        upload_dir = os.path.join(app.static_folder, "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        # 修复路径穿越：拒绝包含路径分隔符的文件名
        safe_filename = file.filename
        if "/" in safe_filename or "\\" in safe_filename or ".." in safe_filename:
            return render_template("upload.html", error="无效的文件名")
        safe_filename = os.path.basename(safe_filename)
        filepath = os.path.join(upload_dir, safe_filename)
        file.save(filepath)

        file_url = url_for("uploaded_file", filename=safe_filename)
        return render_template("upload.html", success=True, file_url=file_url, filename=safe_filename)

    return render_template("upload.html")


@app.route("/uploads/<path:filename>", methods=["GET"])
def uploaded_file(filename):
    """修复：只返回静态文件，移除PHP执行能力。"""
    # 修复路径穿越
    if "/" in filename or "\\" in filename or ".." in filename:
        return "文件不存在", 404

    filepath = os.path.join(app.static_folder, "uploads", os.path.basename(filename))
    if not os.path.exists(filepath):
        return "文件不存在", 404

    # 修复：移除PHP执行能力，所有文件只作为静态文件返回
    return app.send_static_file(f"uploads/{os.path.basename(filename)}")


@app.route("/page")
def page():
    """修复：防路径穿越的动态页面加载。"""
    name = request.args.get("name", "")
    if not name:
        return render_template("index.html", page_content="请指定页面名称")

    # 修复：禁止路径穿越
    if "/" in name or "\\" in name or ".." in name:
        return render_template("index.html", page_content="无效的页面名称")

    # 只允许读取 pages/ 目录下的 .html 文件
    allowed_ext = (".html", ".htm")
    _, ext = os.path.splitext(name)
    if not ext:
        name += ".html"
    elif ext.lower() not in allowed_ext:
        return render_template("index.html", page_content="不允许的文件类型")

    page_path = os.path.join("pages", name)
    content = ""

    if os.path.exists(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = "页面不存在"

    username = session.get("username")
    user_info = get_user(username) if username else None
    return render_template("index.html", user=user_info, page_content=content)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


def get_user_by_id(user_id):
    """根据 ID 查询用户信息（不含密码）。"""
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    cur = conn.execute("SELECT id, username, email, phone, balance FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


@app.route("/profile")
def profile():
    """个人中心：从 session 获取当前登录用户，只能查看自己的资料。"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    user_info = get_user(username)
    return render_template("profile.html", user=user_info)


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值：金额必须为正数，不能超过上限。"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    check_csrf()

    amount_str = request.form.get("amount", "").strip()

    if not amount_str:
        return render_template("profile.html", user=get_user(username), error="请输入充值金额")

    # 检查是否为有效数字
    try:
        amount = float(amount_str)
    except (ValueError, TypeError):
        return render_template("profile.html", user=get_user(username), error="金额必须是有效的数字")

    # 修复负数充值漏洞
    if amount <= 0:
        return render_template("profile.html", user=get_user(username), error="充值金额必须大于0")

    # 修复超大金额漏洞（单次上限100万）
    if amount > 1000000:
        return render_template("profile.html", user=get_user(username), error="单次充值金额不能超过100万元")

    conn = sqlite3.connect("data/users.db")
    conn.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))
    conn.commit()
    conn.close()

    return redirect(url_for("profile"))


@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码：验证 CSRF Token、验证原密码、只能修改自己的密码。"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    check_csrf()

    target_username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")
    old_password = request.form.get("old_password", "")

    if not target_username or not new_password:
        return render_template("profile.html", user=get_user(username), error="用户名和新密码不能为空")

    # 修复：只能修改自己的密码
    if target_username != username:
        return render_template("profile.html", user=get_user(username), error="只能修改自己的密码")

    # 修复：需要验证原密码
    user = get_user(username)
    if not user or user["password"] != old_password:
        return render_template("profile.html", user=get_user(username), error="原密码错误")

    conn = sqlite3.connect("data/users.db")
    conn.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, target_username))
    conn.commit()
    conn.close()

    return redirect(url_for("profile"))


@app.route("/welcome")
def welcome():
    """个性化欢迎页 — 使用模板变量注入，防SSTI。"""
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"
    template = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>欢迎页</title>
<link rel="stylesheet" href="/static/css/style.css">
<style>.welcome-card { text-align: center; padding: 60px 20px; }
.welcome-card h1 { font-size: 36px; color: #667eea; margin-bottom: 16px; }
.welcome-card p { color: #888; font-size: 16px; }</style>
</head>
<body>
<nav class="navbar"><div class="nav-brand">用户管理系统</div>
<div class="nav-menu">
    <a href="/" class="nav-link">首页</a>
    <a href="/welcome" class="nav-link">欢迎页</a>
    <a href="/feedback" class="nav-link">反馈</a>
</div></nav>
<main class="container">
<div class="card welcome-card">
    <h1>欢迎你，{{ name }}！</h1>
    <p>很高兴见到你，祝你使用愉快！</p>
</div></main></body></html>"""
    return render_template_string(template, name=name)


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    """反馈页面 — 使用模板变量注入，防SSTI。"""
    if request.method == "POST":
        name = request.form.get("name", "匿名用户")
        message = request.form.get("message", "")

        template = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>反馈结果</title>
<link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
<nav class="navbar"><div class="nav-brand">用户管理系统</div>
<div class="nav-menu">
    <a href="/" class="nav-link">首页</a>
    <a href="/welcome" class="nav-link">欢迎页</a>
    <a href="/feedback" class="nav-link">反馈</a>
</div></nav>
<main class="container">
<div class="card">
    <h2>{{ name }} 的反馈：</h2>
    <p>{{ message }}</p>
    <a href="/feedback" class="btn btn-primary">继续反馈</a>
</div></main></body></html>"""
        return render_template_string(template, name=name, message=message)

    template = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>反馈</title>
<link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
<nav class="navbar"><div class="nav-brand">用户管理系统</div>
<div class="nav-menu">
    <a href="/" class="nav-link">首页</a>
    <a href="/welcome" class="nav-link">欢迎页</a>
    <a href="/feedback" class="nav-link">反馈</a>
</div></nav>
<main class="container">
<div class="card" style="max-width:500px;margin:0 auto;">
    <h2 class="card-title">意见反馈</h2>
    <form method="post" action="/feedback" class="form">
        <div class="form-group">
            <label for="name">姓名</label>
            <input type="text" id="name" name="name" placeholder="请输入你的姓名" required>
        </div>
        <div class="form-group">
            <label for="message">留言内容</label>
            <textarea id="message" name="message" rows="5" placeholder="请输入你的意见或建议" required
                      style="padding:10px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px;width:100%;resize:vertical;"></textarea>
        </div>
        <button type="submit" class="btn btn-primary">提交反馈</button>
    </form>
</div></main></body></html>"""
    return render_template_string(template)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
