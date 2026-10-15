
import sqlite3
import os
from functools import wraps

from flask import (
    Flask, render_template, redirect,
    url_for, request, session, flash
)
from werkzeug.security import check_password_hash

app = Flask(__name__)
has_alert = True
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "development-key-change-me"
)

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "users.db"
)


# =========================
# データベース
# =========================
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'staff'
            )
        """)


init_db()


# =========================
# ログイン認証チェック
# =========================
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("ログインしてください。")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


# =========================
# トップページ
# =========================
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("products"))

    return redirect(url_for("login"))


# =========================
# ログイン
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect(url_for("products"))

        flash("アカウントまたはパスワードが正しくありません。")

    return render_template("login.html")


# =========================
# ログアウト
# =========================
@app.route("/logout", methods=["GET", "POST"])
def logout():
    if request.method == "POST":
        session.clear()
        return redirect(url_for("login"))

    return render_template("logout.html")


# =========================
# 検知情報：メイン画面
# =========================
@app.route("/products")
@login_required
def products():
    return render_template(
        "products/index.html",
        has_alert=has_alert
    )


# =========================
# アラート一覧
# =========================

@app.route("/products/alerts")
@login_required
def alerts():
    global has_alert
    has_alert = True

    return render_template(
        "products/alerts.html"
    )



# =========================
# 検知履歴
# =========================
@app.route("/products/history")
@login_required
def history():
    return render_template("products/history.html")


# =========================
# 報告画面
# =========================
@app.route("/products/report")
@login_required
def report():
    return render_template("products/report.html")
# 警告
# =========================
# 警告を発生させる（動作確認用）
# =========================
@app.route("/trigger-alert", methods=["POST"])
@login_required
def trigger_alert():
    global has_alert
    has_alert = True
    return redirect(url_for("products"))


# =========================
# 警告を解除する（動作確認用）
# =========================
@app.route("/reset-alert", methods=["POST"])
@login_required
def reset_alert():
    global has_alert
    has_alert = False
    return redirect(url_for("products"))


# =========================
# アプリ起動
# =========================
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
