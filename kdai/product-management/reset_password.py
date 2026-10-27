
import sqlite3
import os
from werkzeug.security import generate_password_hash

db_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "users.db"
)

username = "datou"
new_password = "Admin123!"

conn = sqlite3.connect(db_path)

result = conn.execute(
    "UPDATE users SET password_hash = ? WHERE username = ?",
    (generate_password_hash(new_password), username)
)

conn.commit()
conn.close()

if result.rowcount > 0:
    print("パスワードを変更しました。")
    print("ユーザー名:", username)
    print("新しいパスワード:", new_password)
else:
    print("ユーザーが見つかりません。")
