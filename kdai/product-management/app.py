import sqlite3
import os
from functools import wraps
from datetime import datetime
from zoneinfo import ZoneInfo

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
        # 回収員専用メールボックス
        conn.execute("""
            CREATE TABLE IF NOT EXISTS collector_mailbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_id INTEGER NOT NULL,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                reported_at TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                is_deleted INTEGER NOT NULL DEFAULT 0
            )
        """)
                # 回収依頼テーブル
        conn.execute("""
            CREATE TABLE IF NOT EXISTS collection_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id INTEGER,
                item_name TEXT NOT NULL,
                location TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                memo TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT '未回収',
                reported_at TEXT NOT NULL,
                completed_at TEXT
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
                # 既存の回収員報告履歴をメールとして管理する
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(collection_history)"
            ).fetchall()
        }

        if "sender" not in columns:
            conn.execute("""
                ALTER TABLE collection_history
                ADD COLUMN sender TEXT NOT NULL DEFAULT '回収員'
            """)

        if "is_read" not in columns:
            conn.execute("""
                ALTER TABLE collection_history
                ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0
            """)

        if "is_deleted" not in columns:
            conn.execute("""
                ALTER TABLE collection_history
                ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0
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

@app.route("/send-report", methods=["POST"])
@role_required("admin")
def send_report():
    global has_alert

    current_time = datetime.now(
        ZoneInfo("Asia/Tokyo")
    ).strftime("%Y/%m/%d %H:%M:%S")

    memo = request.form.get("memo", "").strip()

    if not memo:
        memo = "特記事項なし"

    with get_db() as conn:

        # 最新の検知情報を取得
        row = conn.execute("""
            SELECT id, item_name, location, detected_at
            FROM detection_history
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()

        latest_detection = dict(row) if row else {}

        # 回収依頼をSQLiteに保存
        cursor = conn.execute("""
            INSERT INTO collection_requests (
                detection_id,
                item_name,
                location,
                detected_at,
                memo,
                status,
                reported_at
            )
            VALUES (?, ?, ?, ?, ?, '未回収', ?)
        """, (
            latest_detection.get("id"),
            latest_detection.get(
                "item_name", "危険物（要確認）"
            ),
            latest_detection.get(
                "location", "A地区 ごみ投入口"
            ),
            latest_detection.get(
                "detected_at", current_time
            ),
            memo,
            current_time
        ))

        # 管理者の報告履歴
        conn.execute("""
            INSERT INTO report_history (
                reported_at, target, message
            )
            VALUES (?, ?, ?)
        """, (
            current_time,
            "回収員",
            f"危険物回収依頼を送信しました。（メモ：{memo}）"
        ))

        # 回収員全員にメール送信
        collectors = conn.execute("""
            SELECT id, username
            FROM users
            WHERE role = 'collector'
        """).fetchall()

        for collector in collectors:
            conn.execute("""
                INSERT INTO collector_mailbox (
                    recipient_id,
                    sender,
                    subject,
                    message,
                    reported_at,
                    is_read,
                    is_deleted
                )
                VALUES (?, ?, ?, ?, ?, 0, 0)
            """, (
                collector["id"],
                session.get("username", "管理者"),
                "危険物回収依頼",
                f"危険物回収依頼\n"
                f"回収場所：{latest_detection.get('location', 'A地区 ごみ投入口')}\n"
                f"依頼内容：{memo}",
                current_time
            ))

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

    current_time = datetime.now(ZoneInfo("Asia/Tokyo")).strftime("%Y/%m/%d %H:%M:%S")

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

    folder = request.args.get("folder", "inbox")
    q = request.args.get("q", "").strip()
    selected_id = request.args.get("selected", type=int)

    allowed_folders = {"inbox", "unread", "all", "deleted"}

    if folder not in allowed_folders:
        folder = "inbox"

    user_id = session["user_id"]

    with get_db() as conn:

        # メールを開いたら既読にする
        if selected_id is not None and folder != "deleted":
            conn.execute("""
                UPDATE collector_mailbox
                SET is_read = 1
                WHERE id = ?
                  AND recipient_id = ?
                  AND is_deleted = 0
            """, (selected_id, user_id))

        conditions = ["recipient_id = ?"]
        params = [user_id]

        if folder == "deleted":
            conditions.append("is_deleted = 1")
        else:
            conditions.append("is_deleted = 0")

            if folder == "unread":
                conditions.append("(is_read = 0 OR id = ?)")
                params.append(selected_id or -1)

        if q:
            conditions.append("""
                (
                    sender LIKE ?
                    OR subject LIKE ?
                    OR message LIKE ?
                    OR reported_at LIKE ?
                )
            """)

            keyword = f"%{q}%"
            params.extend([keyword] * 4)

        where_sql = " AND ".join(conditions)

        # メール一覧
        messages = conn.execute(f"""
            SELECT
                id,
                recipient_id,
                sender,
                subject,
                message,
                reported_at AS time,
                is_read,
                is_deleted
            FROM collector_mailbox
            WHERE {where_sql}
            ORDER BY id DESC
        """, params).fetchall()

        # 未読件数
        unread_count = conn.execute("""
            SELECT COUNT(*)
            FROM collector_mailbox
            WHERE recipient_id = ?
              AND is_read = 0
              AND is_deleted = 0
        """, (user_id,)).fetchone()[0]

        # 選択したメール
        selected_message = None

        if selected_id is not None:
            selected_message = conn.execute("""
                SELECT *
                FROM collector_mailbox
                WHERE id = ?
                  AND recipient_id = ?
            """, (selected_id, user_id)).fetchone()

    if selected_message and selected_message["is_deleted"]:
        folder = "deleted"

    return render_template(
        "Collector/collection_mailbox.html",
        messages=messages,
        selected_message=selected_message,
        unread_count=unread_count,
        folder=folder,
        q=q
    )


# 回収員：メール削除
@app.route(
    "/collection/mailbox/delete/<int:message_id>",
    methods=["POST"]
)
@role_required("collector")
def collection_mailbox_delete(message_id):

    with get_db() as conn:
        conn.execute("""
            UPDATE collector_mailbox
            SET is_deleted = 1
            WHERE id = ?
              AND recipient_id = ?
        """, (message_id, session["user_id"]))

    flash("メールを削除済みに移動しました。", "success")

    return redirect(url_for("collection_mailbox"))


# 回収員：メール復元
@app.route(
    "/collection/mailbox/restore/<int:message_id>",
    methods=["POST"]
)
@role_required("collector")
def collection_mailbox_restore(message_id):

    with get_db() as conn:
        conn.execute("""
            UPDATE collector_mailbox
            SET is_deleted = 0
            WHERE id = ?
              AND recipient_id = ?
        """, (message_id, session["user_id"]))

    flash("メールを復元しました。", "success")

    return redirect(
        url_for("collection_mailbox", folder="inbox")
    )

#回収員への報告終わり　route
@app.route('/report_completed', methods=['POST'])
def report_completed():

    return render_template('products/report_complete.html')

#回収員
@app.route("/collection")
@role_required("collector")
def collection_page():

    with get_db() as conn:
        detections = conn.execute("""
            SELECT *
            FROM collection_requests
            WHERE status = '未回収'
            ORDER BY id DESC
        """).fetchall()

    return render_template(
        "Collector/collection.html",
        detections=detections
    )
# 回収員：回収完了登録・報告フォーム画面

@app.route("/collection/report-form")
@role_required("collector")
def collection_report_form():

    request_id = request.args.get(
        "request_id", type=int
    )

    with get_db() as conn:
        item = conn.execute("""
            SELECT *
            FROM collection_requests
            WHERE id = ?
              AND status = '未回収'
        """, (request_id,)).fetchone()

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

    current_time = datetime.now(
        ZoneInfo("Asia/Tokyo")
    ).strftime("%Y/%m/%d %H:%M:%S")

    request_id = request.form.get(
        "request_id", type=int
    )

    memo = request.form.get("memo", "").strip()

    if not memo:
        memo = "特記事項なし"

    with get_db() as conn:

        completed_item = conn.execute("""
            SELECT *
            FROM collection_requests
            WHERE id = ?
              AND status = '未回収'
        """, (request_id,)).fetchone()

        if completed_item is None:
            flash("対象の回収依頼が見つかりません。", "warning")
            return redirect(url_for("collection_page"))

        message = (
            f"{completed_item['item_name']} の回収完了"
            f"（場所：{completed_item['location']}、"
            f"メモ：{memo}）"
        )

        # 回収履歴を保存
        conn.execute("""
            INSERT INTO collection_history (
                reported_at,
                target,
                message,
                sender,
                is_read,
                is_deleted
            )
            VALUES (?, ?, ?, ?, 0, 0)
        """, (
            current_time,
            "管理者",
            message,
            session.get("username", "回収員")
        ))

        # 回収依頼を回収済みに変更
        conn.execute("""
            UPDATE collection_requests
            SET status = '回収済み',
                completed_at = ?
            WHERE id = ?
        """, (current_time, request_id))

        # 検知履歴を対応済みに変更
        detection_id = completed_item["detection_id"]

        if detection_id is not None:
            conn.execute("""
                UPDATE detection_history
                SET status = '対応済み'
                WHERE id = ?
            """, (detection_id,))

    flash(
        "回収完了を登録しました。検知履歴も対応済みに更新しました。",
        "success"
    )

    return redirect(url_for("collection_page"))

# 回収員：検知写真・詳細確認画面

@app.route("/collection/detail")
@role_required("collector")
def collection_detail():

    request_id = request.args.get(
        "request_id", type=int
    )

    with get_db() as conn:
        item = conn.execute("""
            SELECT *
            FROM collection_requests
            WHERE id = ?
        """, (request_id,)).fetchone()

    if item is None:
        flash("対象の回収依頼が見つかりません。", "warning")
        return redirect(url_for("collection_page"))

    return render_template(
        "Collector/detail.html",
        item=item
    )
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
# =========================
# 管理者：Outlook風メール受信箱
# =========================

@app.route("/admin/mailbox")
@role_required("admin")
def admin_mailbox():
    folder = request.args.get("folder", "inbox")
    q = request.args.get("q", "").strip()
    selected_id = request.args.get("selected", type=int)

    allowed_folders = {
        "inbox", "unread", "all", "deleted"
    }

    if folder not in allowed_folders:
        folder = "inbox"

    # 選択したメールを開いたら既読にする
    if selected_id is not None and folder != "deleted":
        with get_db() as conn:
            conn.execute("""
                UPDATE collection_history
                SET is_read = 1
                WHERE id = ? AND is_deleted = 0
            """, (selected_id,))

    conditions = []
    params = []

    if folder == "deleted":
        conditions.append("is_deleted = 1")
    else:
        conditions.append("is_deleted = 0")

        if folder == "unread":
            # 選択中のメールは、開いた後も本文を表示できる
            conditions.append(
                "(is_read = 0 OR id = ?)"
            )
            params.append(selected_id or -1)

    if q:
        conditions.append("""
            (
                sender LIKE ?
                OR target LIKE ?
                OR message LIKE ?
                OR reported_at LIKE ?
            )
        """)
        keyword = f"%{q}%"
        params.extend([keyword] * 4)

    where_sql = " AND ".join(conditions)

    with get_db() as conn:
        messages = conn.execute(f"""
            SELECT
                id,
                reported_at AS time,
                sender,
                target,
                message,
                is_read,
                is_deleted
            FROM collection_history
            WHERE {where_sql}
            ORDER BY id DESC
        """, params).fetchall()

        unread_count = conn.execute("""
            SELECT COUNT(*)
            FROM collection_history
            WHERE is_read = 0 AND is_deleted = 0
        """).fetchone()[0]

        selected_message = None

        if selected_id is not None:
            selected_message = conn.execute("""
                SELECT
                    id,
                    reported_at AS time,
                    sender,
                    target,
                    message,
                    is_read,
                    is_deleted
                FROM collection_history
                WHERE id = ?
            """, (selected_id,)).fetchone()

    # 削除済みメールは復元できるようにする
    if selected_message and selected_message["is_deleted"]:
        folder = "deleted"

    return render_template(
        "products/admin_mailbox.html",
        messages=messages,
        selected_message=selected_message,
        unread_count=unread_count,
        folder=folder,
        q=q
    )


# メールを削除済みフォルダへ移動
@app.route(
    "/admin/mailbox/delete/<int:message_id>",
    methods=["POST"]
)
@role_required("admin")
def admin_mailbox_delete(message_id):
    with get_db() as conn:
        conn.execute("""
            UPDATE collection_history
            SET is_deleted = 1
            WHERE id = ?
        """, (message_id,))

    flash("メールを削除済みフォルダへ移動しました。", "success")
    return redirect(url_for("admin_mailbox", folder="inbox"))


# 削除済みメールを復元
@app.route(
    "/admin/mailbox/restore/<int:message_id>",
    methods=["POST"]
)
@role_required("admin")
def admin_mailbox_restore(message_id):
    with get_db() as conn:
        conn.execute("""
            UPDATE collection_history
            SET is_deleted = 0
            WHERE id = ?
        """, (message_id,))

    flash("メールを受信トレイに復元しました。", "success")
    return redirect(url_for("admin_mailbox", folder="inbox"))


# 検知情報履歴：ステータス更新
@app.route(
    "/products/history/update/<int:record_id>",
    methods=["POST"]
)
@role_required("admin")
def update_detection_status(record_id):
    status = request.form.get("status", "").strip()

    # 許可するステータスだけ受け付ける
    allowed_statuses = ["未対応", "対応中", "対応済み"]

    if status not in allowed_statuses:
        flash("不正なステータスです。", "warning")
        return redirect(url_for("history"))

    with get_db() as conn:
        cursor = conn.execute(
            """
            UPDATE detection_history
            SET status = ?
            WHERE id = ?
            """,
            (status, record_id)
        )

        if cursor.rowcount == 0:
            flash("対象の検知履歴が見つかりません。", "warning")
            return redirect(url_for("history"))

    flash("検知履歴のステータスを更新しました。", "success")
    return redirect(url_for("history"))


# =========================
# アプリ起動
# =========================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )

