
import sqlite3
import os

db_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "users.db"
)

print("データベースの場所:", db_path)

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

users = conn.execute(
    "SELECT id, username, role FROM users"
).fetchall()

if users:
    for user in users:
        print(
            "ID:", user["id"],
            "ユーザー名:", user["username"],
            "権限:", user["role"]
        )
else:
    print("ユーザーが登録されていません。")

conn.close()
