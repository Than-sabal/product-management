from werkzeug.utils import secure_filename
from uuid import uuid4
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

# 写真の保存先
UPLOAD_FOLDER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "static",
    "uploads"
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MBまで

ALLOWED_IMAGE_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "webp"
}

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "development-key-change-me"
)

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "users.db"
)

has_alert = False


# =========================
# 共通・データベース
# =========================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def current_time():
    return datetime.now(
        ZoneInfo("Asia/Tokyo")
    ).strftime("%Y/%m/%d %H:%M:%S")



def init_db():
    with get_db() as conn:

        # =========================
        # ユーザー
        # =========================
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'staff'
            )
        """)

        # =========================
        # 検知履歴（先に作成する）
        # =========================
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT NOT NULL,
                location TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT '未対応',
                latitude REAL,
                longitude REAL,
                photo TEXT
            )
        """)

        # 既存DBとの互換性
        detection_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(detection_history)"
            ).fetchall()
        }

        if "latitude" not in detection_columns:
            conn.execute("""
                ALTER TABLE detection_history
                ADD COLUMN latitude REAL
            """)

        if "longitude" not in detection_columns:
            conn.execute("""
                ALTER TABLE detection_history
                ADD COLUMN longitude REAL
            """)

        if "photo" not in detection_columns:
            conn.execute("""
                ALTER TABLE detection_history
                ADD COLUMN photo TEXT
            """)

        request_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(collection_requests)"
            ).fetchall()
        }

        if "photo" not in request_columns:
            conn.execute("""
                ALTER TABLE collection_requests
                ADD COLUMN photo TEXT
            """)

        # 詳細確認状態
        if "confirmed" not in request_columns:
            conn.execute("""
                ALTER TABLE collection_requests
                ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 0
            """)

        if "confirmed_at" not in request_columns:
            conn.execute("""
                ALTER TABLE collection_requests
                ADD COLUMN confirmed_at TEXT
            """)    

        # =========================
        # 回収依頼
        # =========================
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
                completed_at TEXT,
                photo TEXT
            )
        """)

        request_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(collection_requests)"
            ).fetchall()
        }

        if "photo" not in request_columns:
            conn.execute("""
                ALTER TABLE collection_requests
                ADD COLUMN photo TEXT
            """)

        # =========================
        # 回収員メールボックス
        # =========================
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

        # =========================
        # 回収履歴
        # =========================
        conn.execute("""
            CREATE TABLE IF NOT EXISTS collection_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reported_at TEXT NOT NULL,
                target TEXT NOT NULL,
                message TEXT NOT NULL,
                sender TEXT NOT NULL DEFAULT '回収員',
                is_read INTEGER NOT NULL DEFAULT 0,
                is_deleted INTEGER NOT NULL DEFAULT 0
            )
        """)

        # 既存DBとの互換性
        history_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(collection_history)"
            ).fetchall()
        }

        if "sender" not in history_columns:
            conn.execute("""
                ALTER TABLE collection_history
                ADD COLUMN sender TEXT NOT NULL DEFAULT '回収員'
            """)

        if "is_read" not in history_columns:
            conn.execute("""
                ALTER TABLE collection_history
                ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0
            """)

        if "is_deleted" not in history_columns:
            conn.execute("""
                ALTER TABLE collection_history
                ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0
            """)
init_db()



# =========================
# ログイン・権限管理
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

                if role == "collector":
                    return redirect(url_for("collection_page"))

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

    if session.get("role") == "tester":
        return redirect(url_for("tester_panel"))

    if session.get("role") == "collector":
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
            user = conn.execute("""
                SELECT id, username, password_hash, role
                FROM users
                WHERE username = ?
            """, (username,)).fetchone()

        if (
            user
            and check_password_hash(
                user["password_hash"], password
            )
            and user["role"] in ("tester", "collector")
        ):

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            if user["role"] == "tester":
                return redirect(url_for("tester_panel"))

            if user["role"] == "collector":
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
# テスター画面
# =========================

@app.route("/tester")
@role_required("tester")
def tester_panel():

    return render_template(
        "tester.html",
        has_alert=has_alert
    )


# =========================
# テスター：検知・回収員へ直接依頼
# =========================

@app.route("/trigger-test-alert", methods=["POST"])
@role_required("tester")
def trigger_test_alert():

    global has_alert

    now = current_time()

    item_name = "危険物（テスト検知）"
    latitude = request.form.get("latitude", type=float)
    longitude = request.form.get("longitude", type=float)

    # GPS位置の確認
    if (
        latitude is not None and longitude is not None
        and -90 <= latitude <= 90
        and -180 <= longitude <= 180
    ):
        location = "テスター現在地（GPS）"
    else:
        latitude = None
        longitude = None
        location = "A地区 ごみ投入口"

    message = "テストによる危険物検知"
    tester_name = session.get("username", "テスター")

    # 写真アップロード処理
    photo_filename = None
    photo_file = request.files.get("attachment_photo")

    if photo_file and photo_file.filename:

        original_name = secure_filename(photo_file.filename)

        if "." not in original_name:
            flash("画像ファイルの形式を確認してください。", "warning")
            return redirect(url_for("tester_panel"))

        extension = original_name.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_IMAGE_EXTENSIONS:
            flash("JPG、PNG、GIF、WEBP形式の画像を選択してください。", "warning")
            return redirect(url_for("tester_panel"))

        photo_filename = f"{uuid4().hex}.{extension}"

        save_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            photo_filename
        )

        photo_file.save(save_path)

    with get_db() as conn:

        # ① 検知履歴に保存
        cursor = conn.execute("""
            INSERT INTO detection_history (
                item_name,
                location,
                detected_at,
                message,
                status,
                latitude,
                longitude,
                photo
            )
            VALUES (?, ?, ?, ?, '未対応', ?, ?, ?)
        """, (
            item_name,
            location,
            now,
            message,
            latitude,
            longitude,
            photo_filename
        ))

        detection_id = cursor.lastrowid

        # ② 回収依頼に保存
        conn.execute("""
            INSERT INTO collection_requests (
                detection_id,
                item_name,
                location,
                detected_at,
                memo,
                status,
                reported_at,
                photo
            )
            VALUES (?, ?, ?, ?, ?, '未回収', ?, ?)
        """, (
            detection_id,
            item_name,
            location,
            now,
            "テスターからの直接回収依頼",
            now,
            photo_filename
        ))

        # ③ 回収員を取得
        collectors = conn.execute("""
            SELECT id, username
            FROM users
            WHERE role = 'collector'
        """).fetchall()

        # ④ 回収員へ通知
        for collector in collectors:

            mail_message = (
                "テスターからの直接回収依頼\n"
                f"検知物：{item_name}\n"
                f"回収場所：{location}\n"
                f"検知日時：{now}\n"
                f"依頼者：{tester_name}\n"
                + (
                    f"GPS：緯度 {latitude}, 経度 {longitude}\n"
                    if latitude is not None and longitude is not None
                    else "GPS：位置情報なし\n"
                )
                + (
                    f"写真：{photo_filename}\n"
                    if photo_filename
                    else "写真：添付なし\n"
                )
                + "依頼内容：テスターからの直接回収依頼"
            )

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
                tester_name,
                "【直接依頼】危険物回収依頼",
                mail_message,
                now
            ))

    has_alert = True

    flash(
        "危険物を検知し、写真と位置情報を保存して回収員へ直接依頼しました。",
        "success"
    )

    return redirect(url_for("tester_panel"))

# =========================
# 全国マップ：検知位置表示
# =========================

@app.route("/map")
@login_required
def map_view():

    with get_db() as conn:
        rows = conn.execute("""
            SELECT
                id,
                item_name,
                location,
                detected_at,
                status,
                latitude,
                longitude,
                photo,
                message
            FROM detection_history
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
            ORDER BY id DESC
        """).fetchall()

    detections = [dict(row) for row in rows]

    # デバッグ確認
    print("========== 全国マップ確認 ==========")
    print("GPS付き検知件数:", len(detections))

    for item in detections:
        print(
            "ID:", item["id"],
            "場所:", item["location"],
            "緯度:", item["latitude"],
            "経度:", item["longitude"]
        )

    print("===================================")

    return render_template(
        "map.html",
        detections=detections
    )

# =========================
# 回収員：回収依頼一覧
# =========================

@app.route("/collection")
@role_required("collector")
def collection_page():

    with get_db() as conn:

        detections = conn.execute("""
            SELECT
                cr.*,
                dh.latitude AS latitude,
                dh.longitude AS longitude,
                dh.message AS detection_message,
                dh.status AS detection_status
            FROM collection_requests AS cr
            LEFT JOIN detection_history AS dh
                ON cr.detection_id = dh.id
            WHERE cr.status = '未回収'
            AND COALESCE(cr.confirmed, 0) = 0
            ORDER BY cr.id DESC
        """).fetchall()

    # 地図のJavaScriptに渡すため辞書に変換
    map_detections = [
        dict(item) for item in detections
    ]

    return render_template(
        "Collector/collection.html",
        detections=detections,
        map_detections=map_detections
    )


# =========================
# 回収員：メールボックス
# =========================

@app.route("/collection/mailbox")
@role_required("collector")
def collection_mailbox():

    folder = request.args.get("folder", "inbox")
    q = request.args.get("q", "").strip()
    selected_id = request.args.get("selected", type=int)

    if folder not in {"inbox", "unread", "all", "deleted"}:
        folder = "inbox"

    user_id = session["user_id"]

    with get_db() as conn:

        # メールを開いたら既読
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

        unread_count = conn.execute("""
            SELECT COUNT(*)
            FROM collector_mailbox
            WHERE recipient_id = ?
              AND is_read = 0
              AND is_deleted = 0
        """, (user_id,)).fetchone()[0]

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


# =========================
# 回収員：メール削除
# =========================

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


# =========================
# 回収員：メール復元
# =========================

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


# =========================
# 回収員：詳細画面
# =========================

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

# =========================
# 回収員：詳細確認完了
# =========================

@app.route(
    "/collection/confirm/<int:request_id>",
    methods=["POST"]
)
@role_required("collector")
def collection_confirm(request_id):

    now = current_time()
    collector_name = session.get("username", "回収員")

    with get_db() as conn:

        item = conn.execute("""
            SELECT *
            FROM collection_requests
            WHERE id = ?
              AND status = '未回収'
              AND COALESCE(confirmed, 0) = 0
        """, (request_id,)).fetchone()

        if item is None:
            flash("対象の依頼は既に確認済み、または存在しません。", "warning")
            return redirect(url_for("collection_page"))

        # ① 確認済みに変更
        conn.execute("""
            UPDATE collection_requests
            SET confirmed = 1,
                confirmed_at = ?
            WHERE id = ?
              AND COALESCE(confirmed, 0) = 0
        """, (now, request_id))

        # ② 確認履歴に保存
        message = (
            "詳細確認完了\n"
            f"対象物：{item['item_name']}\n"
            f"場所：{item['location']}\n"
            f"検知日時：{item['detected_at']}\n"
            f"確認日時：{now}\n"
            f"確認者：{collector_name}"
        )

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
            now,
            "詳細確認履歴",
            message,
            collector_name
        ))

    flash("詳細を確認し、履歴に保存しました。", "success")

    return redirect(url_for("collection_page"))


# =========================
# 回収員：回収完了報告フォーム
# =========================

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


# =========================
# 回収員：回収完了登録
# =========================

@app.route("/collection/send-report", methods=["POST"])
@role_required("collector")
def collection_send_report():

    now = current_time()

    request_id = request.form.get(
        "request_id", type=int
    )

    memo = request.form.get("memo", "").strip()

    if not memo:
        memo = "特記事項なし"

    collector_name = session.get("username", "回収員")

    with get_db() as conn:

        # 回収対象を確認
        item = conn.execute("""
            SELECT *
            FROM collection_requests
            WHERE id = ?
              AND status = '未回収'
        """, (request_id,)).fetchone()

        if item is None:
            flash("対象の回収依頼が見つかりません。", "warning")
            return redirect(url_for("collection_page"))

        # ① 回収履歴に保存
        message = (
            f"回収完了報告\n"
            f"回収物：{item['item_name']}\n"
            f"回収場所：{item['location']}\n"
            f"回収日時：{now}\n"
            f"報告者：{collector_name}\n"
            f"報告内容：{memo}"
        )

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
            now,
            "回収履歴",
            message,
            collector_name
        ))

        # ② 回収依頼を回収済みに変更
        conn.execute("""
            UPDATE collection_requests
            SET status = '回収済み',
                completed_at = ?
            WHERE id = ?
              AND status = '未回収'
        """, (now, request_id))

        # ③ 検知履歴を対応済みに変更
        detection_id = item["detection_id"]

        if detection_id is not None:
            conn.execute("""
                UPDATE detection_history
                SET status = '対応済み'
                WHERE id = ?
            """, (detection_id,))

    flash(
        "回収完了を登録しました。",
        "success"
    )

    return redirect(url_for("collection_page"))


# =========================
# 回収員：回収履歴
# =========================

@app.route("/collection/history")
@role_required("collector")
def collection_history():

    with get_db() as conn:

        report_list = conn.execute("""
            SELECT
                id,
                reported_at AS time,
                target,
                message
            FROM collection_history
            WHERE sender = ?
            ORDER BY id DESC
        """, (session.get("username"),)).fetchall()

    return render_template(
        "Collector/collection_history.html",
        report_list=report_list
    )


@app.route("/collection/history/delete/<int:report_id>", methods=["POST"])
@role_required("collector")
def collection_history_delete(report_id):

    with get_db() as conn:
        conn.execute("""
            DELETE FROM collection_history
            WHERE id = ?
            AND sender = ?
        """, (report_id, session.get("username")))

        conn.commit()

    flash("報告履歴を削除しました。", "success")

    return redirect(url_for("collection_history"))



# =========================
# 回収員：履歴削除
# =========================

@app.route(
    "/collection/history/delete/<int:record_id>",
    methods=["POST"]
)
@role_required("collector")
def delete_collection_history(record_id):

    with get_db() as conn:
        conn.execute("""
            DELETE FROM collection_history
            WHERE id = ?
              AND sender = ?
        """, (
            record_id,
            session.get("username")
        ))

    flash("回収履歴を削除しました。", "success")

    return redirect(url_for("collection_history"))


# =========================
# アプリ起動
# =========================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
