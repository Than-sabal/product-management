
import sqlite3
from getpass import getpass
from werkzeug.security import generate_password_hash

DATABASE = "users.db"

username = input("アカウント名: ").strip()
password = getpass("パスワード: ")

if not username or not password:
    print("アカウント名とパスワードを入力してください。")
    raise SystemExit(1)

with sqlite3.connect(DATABASE) as conn:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'staff'
        )
    """)

    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) "
            "VALUES (?, ?, ?)",
            (username, generate_password_hash(password), "admin")
        )
        print("管理者アカウントを登録しました。")
    except sqlite3.IntegrityError:
        print("そのアカウント名はすでに登録されています。")
