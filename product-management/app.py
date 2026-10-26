from flask import Flask, render_template, redirect, url_for, request
from datetime import datetime

app = Flask(__name__)

has_alert = False
detection_history =[]
report_history = []
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

    return render_template("products/alerts.html",has_alert= has_alert)

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

#回収員 へ 報告する
@app.route("/products/report-form", methods=["GET"])

def report_form():

    return render_template("products/report_form.html")

#報告 Form 

@app.route("/send-report", methods=["POST"])

def send_report():

    current_time = datetime.now().strftime("%Y/%m/%d %H:%M")

    memo = request.form.get("memo", "特記事項なし")

    new_report = {

        "time": current_time,

        "target": "回収員 (Staff)",

        "message": f"危険物回収依頼を送信しました。(メモ: {memo})"

    }

    report_history.insert(0, new_report)

    #報告履歴 

    return render_template('products/report_complete.html')

#報告履歴 

@app.route("/products/report-history", methods=["GET"])

def report_history_page():

    return render_template("products/report_history.html", report_list=report_history)

#回収員への報告終わり　route
@app.route('/report_completed', methods=['POST'])
def report_completed():

    return render_template('products/report_complete.html')

#回収員
@app.route('/collection')

def collection_view():
    detections = [
        {

            'id': 1,

            'item_name': 'スプレー缶',

            'location': '第1作業区',

            'detected_at': '2026/10/21 10:15'

        }

    ]

    return render_template('Collector/collection.html', detections=detections)
 
# 回収員：回収完了登録・報告フォーム画面

@app.route("/collection/report-form")

def collection_report_form():

    return render_template("Collector/collection_report.html")

# 回収員：回収完了登録・報告の送信処理

@app.route("/collection/send-report", methods=["POST"])

def collection_send_report():

    current_time = datetime.now().strftime("%Y/%m/%d %H:%M")

    memo = request.form.get("memo", "特記事項なし")

    new_report = {

        "time": current_time,

        "target": "回収員 (Staff)",

        "message": f"回収完了登録: {memo}"

    }

    report_history.insert(0, new_report)

    return render_template("Collector/collection_report_complete.html")

# 回収員：検知写真・詳細確認画面
@app.route("/collection/detail")
def collection_detail():
   return render_template("Collector/detail.html")

# 回収員：過去の報告履歴画面
@app.route("/collection/history")
def collection_history():
# 回収員が過去に行った報告のリスト
   return render_template("Collector/collection_history.html", report_list=report_history)

# 管理者：回収員からの報告受信箱 (Mailbox)
@app.route("/admin/mailbox")
def admin_mailbox():
   # 回収員から送られてきたレポート一覧を管理者画面に表示する
   return render_template("products/admin_mailbox.html", report_list=report_history)

if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )