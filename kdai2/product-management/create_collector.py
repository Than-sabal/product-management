import os
import sqlite3
from getpass import getpass
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "users.db")

username = "collector01"

password = getpass("回収員のパスワードを入力してください: ")
confirm = getpass("もう一度入力してください: ")

if not password:
    print("パスワードが空です。")
    raise SystemExit(1)

if password != confirm:
    print("パスワードが一致しません。")
    raise SystemExit(1)

if not os.path.exists(DATABASE):
    print("users.db が見つかりません。")
    raise SystemExit(1)

with sqlite3.connect(DATABASE) as conn:
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if existing:
        print("collector01 はすでに登録されています。")
    else:
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (
                username,
                generate_password_hash(password),
                "collector"
            )
        )
        print("回収員アカウントを作成しました。")

        print("ユーザー名: collector01")
