
import sqlite3
import os
from werkzeug.security import generate_password_hash

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "users.db"
)

username = "tester"
password = "Tester123!"

with sqlite3.connect(DATABASE) as conn:
    user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if user:
        print("テスターアカウントはすでに存在します。")
    else:
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (
                username,
                generate_password_hash(password),
                "tester"
            )
        )
        print("テスターアカウントを作成しました！")
        print("ユーザー名：tester")
        print("パスワード：Tester123!")
