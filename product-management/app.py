from flask import Flask, render_template, redirect, url_for, request
app = Flask(__name__)
# =========================
# ログイン
# =========================
@app.route("/")
def index():
   return redirect(url_for("login"))
# login route
@app.route("/login", methods=["GET", "POST"])
def login():
   if request.method == "POST":
       return redirect(url_for("products"))
   return render_template("login.html")
@app.route("/logout")
def logout():
   return redirect(url_for("login"))
# =========================
@app.route("/products")
def products():
   return render_template("/products/index.html")

@app.route("/products/alerts")
def alerts():
   return render_template("products/alerts.html")
@app.route("/products/history")
def history():
   return render_template("products/history.html")
@app.route("/products/report")
def report():
   return render_template("products/report.html")

if __name__ == "__main__":
   app.run(
       host="127.0.0.1",
       port=5000,
       debug=True
   )