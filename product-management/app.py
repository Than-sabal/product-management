from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)


# =========================
# ログイン
# =========================

@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/logout")
def logout():
    return redirect(url_for("login"))


# =========================
# ダッシュボード
# =========================

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# =========================
# 商品管理
# =========================

@app.route("/products")
def products():
    return render_template("products/index.html")


@app.route("/products/create")
def product_create():
    return render_template("products/create.html")


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    return render_template(
        "products/detail.html",
        product_id=product_id
    )


@app.route("/products/<int:product_id>/edit")
def product_edit(product_id):
    return render_template(
        "products/edit.html",
        product_id=product_id
    )


@app.route("/products/<int:product_id>/delete")
def product_delete(product_id):
    return render_template(
        "products/delete.html",
        product_id=product_id
    )


# =========================
# カテゴリ
# =========================

@app.route("/categories")
def categories():
    return render_template("categories/index.html")


# =========================
# 在庫
# =========================

@app.route("/stocks")
def stocks():
    return render_template("stocks/index.html")


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
