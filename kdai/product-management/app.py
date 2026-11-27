
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

# =========================
# 基本設定
# =========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(
    BASE_DIR, "static", "uploads"
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

ALLOWED_IMAGE_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "webp"
}

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "development-key-change-me"
)

DATABASE = os.path.join(BASE_DIR, "users.db")

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


def get_columns(conn, table_name):
    return {
        row["name"]
        for row in conn.execute(
            f"PRAGMA table_info({table_name})"
        ).fetchall()
    }


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
        # 検知履歴
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

        detection_columns = get_columns(
            conn, "detection_history"
        )

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

        # =========================
        # 回収依頼
        # 必ず作成してから不足カラムを確認する
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
                photo TEXT,
                confirmed INTEGER NOT NULL DEFAULT 0,
                confirmed_at TEXT
            )
        """)

        request_columns = get_columns(
            conn, "collection_requests"
        )

        if "photo" not in request_columns:
            conn.execute("""
                ALTER TABLE collection_requests
                ADD COLUMN photo TEXT
            """)

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

        history_columns = get_columns(
            conn, "collection_history"
        )

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


# アプリ起動時にDBを初期化
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

    latitude = request.form.get(
        "latitude", type=float
    )

    longitude = request.form.get(
        "longitude", type=float
    )

    # GPS位置の確認
    if (
        latitude is not None
        and longitude is not None
        and -90 <= latitude <= 90
        and -180 <= longitude <= 180
    ):

        location = "テスター現在地（GPS）"

    else:

        latitude = None
        longitude = None
        location = "A地区 ごみ投入口"

    message = "テストによる危険物検知"

    # 写真アップロード
    photo_filename = None

    photo_file = request.files.get(
        "attachment_photo"
    )

    if photo_file and photo_file.filename:

        original_name = secure_filename(
            photo_file.filename
        )

        if "." not in original_name:

            flash(
                "画像ファイルの形式を確認してください。",
                "warning"
            )

            return redirect(
                url_for("tester_panel")
            )

        extension = original_name.rsplit(
            ".", 1
        )[1].lower()

        if extension not in ALLOWED_IMAGE_EXTENSIONS:

            flash(
                "JPG、PNG、GIF、WEBP形式の画像を選択してください。",
                "warning"
            )

            return redirect(
                url_for("tester_panel")
            )

        photo_filename = (
            f"{uuid4().hex}.{extension}"
        )

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


    has_alert = True

    flash(
        "危険物を検知し、写真と位置情報を保存して回収依頼を登録しました。",
        "success"
    )

    return redirect(
        url_for("tester_panel")
    )


# =========================
# 全国マップ：検知位置表示
# =========================

@app.route('/map')
@login_required
def map_page():

    # DATABASE はこのファイル上部で定義しているDBパスを使用
    with get_db() as conn:
        detections = conn.execute("""
            SELECT
                dh.id,
                dh.item_name,
                dh.location,
                dh.detected_at,
                dh.latitude,
                dh.longitude,
                dh.status,
                dh.message,
                dh.photo,
                (
                    SELECT cr.id
                    FROM collection_requests AS cr
                    WHERE cr.detection_id = dh.id
                    ORDER BY cr.id DESC
                    LIMIT 1
                ) AS request_id
            FROM detection_history AS dh
            WHERE dh.latitude IS NOT NULL
            AND dh.longitude IS NOT NULL
            ORDER BY dh.id DESC
        """).fetchall()

        detections = [dict(row) for row in detections]

    return render_template(
        'map.html',
        detections=detections
    )

# =========================
# 回収員：回収依頼一覧
# =========================


# =========================
# 回収員：回収依頼一覧・検索
# =========================


# =========================
# 回収員：回収依頼一覧・検索
# =========================

@app.route("/collection")
@role_required("collector")
def collection_page():

    keyword = request.args.get(
        "keyword", ""
    ).strip()

    # =========================
    # 検索文字列から日時を取り出す
    # =========================

    import re

    search_datetime = None
    search_time_only = None

    # 例：2026/11/25 10:30
    # 例：2026-11-25 10:30
    datetime_pattern = (
        r"(20\d{2})[/-](\d{1,2})[/-](\d{1,2})"
        r"(?:\s+(\d{1,2}):(\d{2}))?"
    )

    match = re.search(datetime_pattern, keyword)

    if match:
        year, month, day, hour, minute = match.groups()

        try:
            search_datetime = datetime(
                int(year),
                int(month),
                int(day),
                int(hour or 0),
                int(minute or 0)
            )

            keyword = (
                keyword[:match.start()] +
                keyword[match.end():]
            ).strip()

        except ValueError:
            search_datetime = None

    else:
        # 例：10:30 のような時刻だけの検索
        time_pattern = r"(?<!\d)(\d{1,2}):(\d{2})(?!\d)"
        match = re.search(time_pattern, keyword)

        if match:
            try:
                search_time_only = (
                    int(match.group(1)),
                    int(match.group(2))
                )

                if (
                    not 0 <= search_time_only[0] <= 23
                    or not 0 <= search_time_only[1] <= 59
                ):
                    search_time_only = None
                else:
                    keyword = (
                        keyword[:match.start()] +
                        keyword[match.end():]
                    ).strip()

            except ValueError:
                search_time_only = None

    # =========================
    # データ取得
    # =========================

    with get_db() as conn:

        sql = """
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
        """

        params = []

        # 場所・検知内容・備考の検索
        if keyword:

            sql += """
                AND (
                    cr.location LIKE ?
                    OR cr.item_name LIKE ?
                    OR cr.memo LIKE ?
                    OR dh.message LIKE ?
                )
            """

            search_word = f"%{keyword}%"

            params.extend([
                search_word,
                search_word,
                search_word,
                search_word
            ])

        sql += " ORDER BY cr.id DESC"

        detections = conn.execute(
            sql,
            params
        ).fetchall()

    detections = [dict(item) for item in detections]

    # =========================
    # 検知時刻が指定された場合
    # 近い順に並べ替える
    # =========================

    def parse_detected_at(value):

        if not value:
            return None

        formats = [
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%d %H:%M",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y/%m/%d",
            "%Y-%m-%d"
        ]

        for fmt in formats:
            try:
                return datetime.strptime(value, fmt)
            except (ValueError, TypeError):
                continue

        return None

    if search_datetime:

        detections.sort(
            key=lambda item: (
                abs(
                    (
                        parse_detected_at(item.get("detected_at"))
                        or datetime.max
                    ) - search_datetime
                ).total_seconds()
                if parse_detected_at(item.get("detected_at"))
                else float("inf")
            )
        )

    elif search_time_only:

        target_seconds = (
            search_time_only[0] * 3600
            + search_time_only[1] * 60
        )

        def time_distance(item):

            detected = parse_detected_at(
                item.get("detected_at")
            )

            if detected is None:
                return float("inf")

            detected_seconds = (
                detected.hour * 3600
                + detected.minute * 60
                + detected.second
            )

            difference = abs(
                detected_seconds - target_seconds
            )

            # 23:59 と 00:01 のような日付をまたぐ差も考慮
            return min(
                difference,
                86400 - difference
            )

        detections.sort(key=time_distance)

    # =========================
    # 地図に渡すデータ
    # =========================

    map_detections = [
        dict(item) for item in detections
    ]

    return render_template(
        "Collector/collection.html",
        detections=detections,
        map_detections=map_detections
    )




# =========================
# 回収員：詳細画面
# =========================

@app.route("/collection/detail")
@role_required("collector")
def collection_detail():

    request_id = request.args.get("request_id", type=int)

    if request_id is None:
        flash("対象の回収依頼が指定されていません。", "warning")
        return redirect(url_for("collection_page"))

    now = current_time()
    collector_name = session.get("username", "回収員")

    with get_db() as conn:

        # 未回収の依頼を取得
        item = conn.execute("""
            SELECT *
            FROM collection_requests
            WHERE id = ?
              AND status = '未回収'
        """, (request_id,)).fetchone()

        if item is None:
            flash("対象の回収依頼が見つからないか、回収完了済みです。", "warning")
            return redirect(url_for("collection_page"))

        # 詳細画面を初めて開いたタイミングで確認済みにする
        if int(item["confirmed"] or 0) == 0:
            conn.execute("""
                UPDATE collection_requests
                SET confirmed = 1,
                    confirmed_at = ?,
                    status = '未回収'
                WHERE id = ?
                  AND status = '未回収'
                  AND COALESCE(confirmed, 0) = 0
            """, (now, request_id))

            # 確認履歴を一度だけ記録
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
                    reported_at, target, message, sender, is_read, is_deleted
                ) VALUES (?, ?, ?, ?, 0, 0)
            """, (now, "詳細確認履歴", message, collector_name))

        # 更新後の状態で詳細画面を表示
        item = conn.execute("""
            SELECT *
            FROM collection_requests
            WHERE id = ?
        """, (request_id,)).fetchone()

    return render_template(
        "Collector/detail.html",
        item=item
    )


# =========================
# 回収員：回収完了
# =========================

@app.route(
    "/collection/complete/<int:request_id>",
    methods=["POST"]
)
@role_required("collector")
def collection_complete(request_id):

    now = current_time()
    collector_name = session.get("username", "回収員")

    with get_db() as conn:

        item = conn.execute("""
            SELECT *
            FROM collection_requests
            WHERE id = ?
              AND status = '未回収'
        """, (request_id,)).fetchone()

        if item is None:
            flash(
                "対象の回収依頼が見つからないか、すでに回収完了しています。",
                "warning"
            )
            return redirect(url_for("collection_page"))

        # 回収完了状態に更新する
        conn.execute("""
            UPDATE collection_requests
            SET status = '回収完了',
                completed_at = ?
            WHERE id = ?
              AND status = '未回収'
        """, (now, request_id))

        # 元の検知履歴も対応済みにする
        if item["detection_id"] is not None:
            conn.execute("""
                UPDATE detection_history
                SET status = '対応済み'
                WHERE id = ?
            """, (item["detection_id"],))

        # 回収完了履歴を保存する
        message = (
            "回収完了\n"
            f"対象物：{item['item_name']}\n"
            f"場所：{item['location']}\n"
            f"検知日時：{item['detected_at']}\n"
            f"回収完了日時：{now}\n"
            f"回収員：{collector_name}"
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
            "回収完了履歴",
            message,
            collector_name
        ))

    flash("回収が完了し、履歴に保存しました。", "success")
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
        """, (
            session.get("username"),
        )).fetchall()

    return render_template(
        "Collector/collection_history.html",
        report_list=report_list
    )


# =========================
# 回収員：履歴削除
# =========================

@app.route(
    "/collection/history/delete/<int:report_id>",
    methods=["POST"]
)
@role_required("collector")
def collection_history_delete(report_id):

    with get_db() as conn:

        conn.execute("""
            DELETE FROM collection_history
            WHERE id = ?
            AND sender = ?
        """, (
            report_id,
            session.get("username")
        ))

    flash(
        "報告履歴を削除しました。",
        "success"
    )

    return redirect(
        url_for("collection_history")
    )


# =========================
# アプリ起動
# =========================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
