import sqlite3
import os
from functools import wraps
from datetime import datetime

from flask import (
    Flask, render_template, redirect,
    url_for, request, session, flash
)
from werkzeug.security import check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "development-key-change-me"
)

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "users.db"
)

has_alert = False
detection_history = []


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
# ログイン・権限チェック
# =========================

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("ログインしてください。")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def role_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped_view(*args, **kwargs):
            role = session.get("role")

            if role not in allowed_roles:
                flash("この画面を利用する権限がありません。")

                if role == "tester":
                    return redirect(url_for("tester_panel"))

                if role == "admin":
                    return redirect(url_for("products"))

                session.clear()
                return redirect(url_for("login"))

            return view(*args, **kwargs)

        return wrapped_view

    return decorator


# =========================
# トップページ
# =========================

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") == "admin":
        return redirect(url_for("products"))

    if session.get("role") == "tester":
        return redirect(url_for("tester_panel"))

    session.clear()
    return redirect(url_for("login"))


# =========================
# ログイン
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get(
            "username", ""
        ).strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                """
                SELECT id, username, password_hash, role
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

        if (
            user
            and check_password_hash(
                user["password_hash"], password
            )
            and user["role"] in ("admin", "tester")
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            if user["role"] == "admin":
                return redirect(url_for("products"))

            return redirect(url_for("tester_panel"))

        flash("アカウントまたはパスワードが正しくありません。")

    return render_template("login.html")


# =========================
# ログアウト
# =========================

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================
# 管理者：モニタリング画面
# =========================

@app.route("/products")
@role_required("admin")
def products():
    return render_template(
        "products/index.html",
        has_alert=has_alert
    )


# =========================
# 管理者：危険物検知情報
# =========================

@app.route("/products/alerts")
@role_required("admin")
def alerts():
    return render_template(
        "products/alerts.html",
        has_alert=has_alert
    )


# =========================
# 管理者：検知履歴
# =========================

@app.route("/products/history")
@role_required("admin")
def history():
    return render_template(
        "products/history.html",
        detection_history=detection_history
    )


# =========================
# 管理者：報告画面
# =========================

@app.route("/products/report")
@role_required("admin")
def report():
    return render_template("products/report.html")

# =========================
# 管理者：報告履歴
# =========================

report_history = []


@app.route("/send-report", methods=["POST"])
@role_required("admin")
def send_report():
    global has_alert

    current_time = datetime.now().strftime("%Y/%m/%d %H:%M")
    memo = request.form.get("memo", "").strip()

    if not memo:
        memo = "特記事項なし"

    # 報告履歴に追加する（既存の履歴は消さない）
    report_history.insert(0, {
        "time": current_time,
        "target": "回収員",
        "message": f"危険物回収依頼を送信しました。（メモ：{memo}）"
    })

    # 現在の危険物アラートだけ解除する
    has_alert = False

    flash("報告を送信しました。", "success")

    # 正常画面へ戻る
    return redirect(url_for("products"))



@app.route("/products/report-history")
@role_required("admin")
def report_history_page():
    return render_template(
        "products/report_history.html",
        report_list=report_history
    )



# =========================
# 管理者：動作確認用の警告発生
# =========================

@app.route("/trigger-alert", methods=["POST"])
@role_required("admin")
def trigger_alert():
    global has_alert
    has_alert = True
    return redirect(url_for("products"))


# =========================
# 管理者：警告解除
# =========================

@app.route("/reset-alert", methods=["POST"])
@role_required("admin")
def reset_alert():
    global has_alert
    has_alert = False
    return redirect(url_for("products"))


# =========================
# テスター専用画面
# =========================
@app.route("/tester")
@role_required("tester")
def tester_panel():
    return render_template(
        "tester.html",
        has_alert=has_alert
    )


# =========================
# テスター：検知テスト
# =========================

@app.route("/trigger-test-alert", methods=["POST"])
@role_required("tester")
def trigger_test_alert():
    global has_alert
    has_alert = True

    detection_history.insert(0, {
        "time": datetime.now().strftime("%Y/%m/%d %H:%M"),
        "location": "A地区 ごみ投入口",
        "message": "テストによる危険物検知"
    })

    return redirect(url_for("tester_panel"))


# =========================
# アプリ起動
# =========================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
