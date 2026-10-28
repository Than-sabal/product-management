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
report_history = []  # 管理者の報告履歴


# =========================
# データベース
# =========================


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# データベース初期化
def init_db():
    with get_db() as conn:

        # ユーザーテーブル
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'staff'
            )
        """)

        # 検知情報履歴テーブル
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT NOT NULL,
                location TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT '未対応'
            )
        """)

        # 管理者の報告履歴テーブル
        conn.execute("""
            CREATE TABLE IF NOT EXISTS report_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reported_at TEXT NOT NULL,
                target TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)

        # 回収員の報告履歴テーブル
        conn.execute("""
            CREATE TABLE IF NOT EXISTS collection_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reported_at TEXT NOT NULL,
                target TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)


# アプリ起動時にデータベースを初期化
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

    if session["role"] == "collector":
        return redirect(url_for("collection_page"))

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
            and user["role"] in ("admin", "tester","collector")
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]


            if user["role"] == "admin":
                return redirect(url_for("products"))

            elif user["role"] == "tester":
                return redirect(url_for("tester_panel"))

            elif user["role"] == "collector":
                return redirect(url_for("collection_page"))

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

    with get_db() as conn:
        detection_history = conn.execute("""
            SELECT
                id,
                item_name,
                location,
                detected_at AS time,
                message,
                status
            FROM detection_history
            ORDER BY id DESC
        """).fetchall()

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

collection_history_list = []
# 管理者から回収員へ送信された危険物
collection_requests = []

# 回収依頼のID
next_collection_id = 1


@app.route("/send-report", methods=["POST"])
@role_required("admin")
def send_report():
    global has_alert, next_collection_id

    current_time = datetime.now().strftime("%Y/%m/%d %H:%M")
    memo = request.form.get("memo", "").strip()

    if not memo:
        memo = "特記事項なし"

    # 最新の検知情報を取得
    latest_detection = (
        detection_history[0] if detection_history else {}
    )

    # 回収員への依頼を登録
    collection_requests.insert(0, {
        "id": next_collection_id,
        "item_name": "危険物（要確認）",
        "location": latest_detection.get(
            "location", "A地区 ごみ投入口"
        ),
        "detected_at": latest_detection.get(
            "time", current_time
        ),
        "memo": memo,
        "status": "未回収",
        "reported_at": current_time
    })

    next_collection_id += 1

    # 管理者の報告履歴も残す

    with get_db() as conn:
        conn.execute("""
            INSERT INTO report_history (reported_at, target, message)
            VALUES (?, ?, ?)
        """, (
            current_time,
            "回収員",
            f"危険物回収依頼を送信しました。（メモ：{memo}）"
        ))

    # 現在の警告だけ解除
    has_alert = False

    flash("報告を送信しました。", "success")
    return redirect(url_for("products"))



@app.route("/products/report-history")
@role_required("admin")
def report_history_page():
    with get_db() as conn:
        report_list = conn.execute("""
            SELECT id, reported_at AS time, target, message
            FROM report_history
            ORDER BY id DESC
        """).fetchall()

    print("報告履歴画面に渡す件数:", len(report_list))
    print("報告履歴データ:", [dict(row) for row in report_list])

    return render_template(
        "products/report_history.html",
        report_list=report_list
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

    current_time = datetime.now().strftime(
        "%Y/%m/%d %H:%M:%S"
    )

    item_name = "危険物（テスト検知）"
    location = "A地区 ごみ投入口"
    message = "テストによる危険物検知"

    # データベースに検知情報を保存
    with get_db() as conn:
        conn.execute("""
            INSERT INTO detection_history (
                item_name,
                location,
                detected_at,
                message,
                status
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            item_name,
            location,
            current_time,
            message,
            "未対応"
        ))

    has_alert = True

    return redirect(url_for("tester_panel"))

# 回収員専用メールボックス
@app.route("/collection/mailbox")
@role_required("collector")
def collection_mailbox():
    with get_db() as conn:
        messages = conn.execute("""
            SELECT id, reported_at AS time, target, message
            FROM report_history
            ORDER BY id DESC
        """).fetchall()

    return render_template(
        "Collector/collection_mailbox.html",
        messages=messages
    )

#回収員への報告終わり　route
@app.route('/report_completed', methods=['POST'])
def report_completed():

    return render_template('products/report_complete.html')

#回収員
@app.route("/collection")
@role_required("collector")
def collection_page():
    # 未回収の危険物だけを表示
    detections = [
        item for item in collection_requests
        if item["status"] == "未回収"
    ]

    return render_template(
        "Collector/collection.html",
        detections=detections
    )
# 回収員：回収完了登録・報告フォーム画面

@app.route("/collection/report-form")
@role_required("collector")
def collection_report_form():
    request_id = request.args.get("request_id", type=int)

    item = next(
        (
            item for item in collection_requests
            if item["id"] == request_id
            and item["status"] == "未回収"
        ),
        None
    )

    if item is None:
        flash("対象の回収依頼が見つかりません。", "warning")
        return redirect(url_for("collection_page"))

    return render_template(
        "Collector/collection_report.html",
        item=item
    )

# 回収員：回収完了登録・報告の送信処理
@app.route("/collection/send-report", methods=["POST"])
@role_required("collector")
def collection_send_report():
    current_time = datetime.now().strftime("%Y/%m/%d %H:%M")
    request_id = request.form.get("request_id", type=int)
    memo = request.form.get("memo", "").strip()

    if not memo:
        memo = "特記事項なし"

    # 管理者から届いた未回収の依頼を探す
    completed_item = next(
        (
            item for item in collection_requests
            if item["id"] == request_id
            and item["status"] == "未回収"
        ),
        None
    )

    if completed_item is None:
        flash("対象の回収依頼が見つかりません。", "warning")
        return redirect(url_for("collection_page"))

    # 回収完了を登録
    completed_item["status"] = "回収済み"
    completed_item["completed_at"] = current_time

    # 回収員の報告履歴に保存
    message = (
        f"{completed_item['item_name']} の回収完了"
        f"（場所：{completed_item['location']}、メモ：{memo}）"
    )

    with get_db() as conn:
        conn.execute("""
            INSERT INTO collection_history (reported_at, target, message)
            VALUES (?, ?, ?)
        """, (current_time, "管理者", message))
    flash("回収完了を登録し、管理者へ報告しました。", "success")

    return redirect(url_for("collection_page"))

# 回収員：検知写真・詳細確認画面

@app.route("/collection/detail")
def collection_detail():
    return render_template("Collector/detail.html")

# 回収員：過去の報告履歴画面

@app.route("/collection/history")
@role_required("collector")
def collection_history():
    with get_db() as conn:
        report_list = conn.execute("""
            SELECT id, reported_at AS time, target, message
            FROM collection_history
            ORDER BY id DESC
        """).fetchall()

    print("回収員の報告履歴件数:", len(report_list))

    return render_template(
        "Collector/collection_history.html",
        report_list=report_list
    )

# 検知情報履歴：1件削除
@app.route("/products/history/delete/<int:record_id>", methods=["POST"])
@role_required("admin")
def delete_detection_history(record_id):
    with get_db() as conn:
        conn.execute(
            "DELETE FROM detection_history WHERE id = ?",
            (record_id,)
        )

    flash("検知情報履歴を削除しました。", "success")
    return redirect(url_for("history"))


# 管理者の報告履歴：1件削除
@app.route("/products/report-history/delete/<int:record_id>", methods=["POST"])
@role_required("admin")
def delete_report_history(record_id):
    with get_db() as conn:
        conn.execute(
            "DELETE FROM report_history WHERE id = ?",
            (record_id,)
        )

    flash("報告履歴を削除しました。", "success")
    return redirect(url_for("report_history_page"))


# 回収員の報告履歴：1件削除
@app.route("/collection/history/delete/<int:record_id>", methods=["POST"])
@role_required("collector")
def delete_collection_history(record_id):
    with get_db() as conn:
        conn.execute(
            "DELETE FROM collection_history WHERE id = ?",
            (record_id,)
        )

    flash("回収員の報告履歴を削除しました。", "success")
    return redirect(url_for("collection_history"))


# 管理者：回収員からの報告受信箱 (Mailbox)
@app.route("/admin/mailbox")
def admin_mailbox():
    # 回収員から送られてきたレポート一覧を管理者画面に表示する
    return render_template("products/admin_mailbox.html", report_list=report_history)

# =========================
# アプリ起動
# =========================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
