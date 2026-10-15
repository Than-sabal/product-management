from flask import Flask, render_template, redirect, url_for, request

app = Flask(__name__)

has_alert = False

# =========================

# ログイン

# =========================

@app.route("/")

def index():

    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])

def login():

    if request.method == "POST":

        return redirect(url_for("products"))

    return render_template("login.html")

@app.route("/logout")

def logout():

    return redirect(url_for("login"))

# =========================

# モニタリング ＆ アラート

# =========================

@app.route("/products")

def products():

    global has_alert

    return render_template("products/index.html", has_alert=has_alert)

@app.route("/products/alerts")

def alerts():

    return render_template("products/alerts.html")

@app.route("/products/history")

def history():

    return render_template("products/history.html")

@app.route("/products/report")

def report():

    return render_template("products/report.html")
   

@app.route("/trigger-alert")

def trigger_alert():

    global has_alert

    has_alert = True

    return redirect(url_for('products'))


@app.route("/reset-alert")

def reset_alert():

    global has_alert

    has_alert = False

    return redirect(url_for('products'))

@app.route("/tester")

def tester_panel():

    return render_template("tester.html")

@app.route("/trigger-test-alert", methods=["POST"])

def trigger_test_alert():

    global has_alert

    has_alert = True

    return redirect(url_for('tester_panel'))
 

if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )
 