import os
import csv
import json
import sqlite3
from flask import Flask, render_template, request, send_file, jsonify
from checks import analyze_url

APP_TITLE = "Detector de Phishing"
DB_PATH = "history.db"
BRANDS_FILE = "brands.txt"

def ensure_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, url TEXT, domain TEXT, score INTEGER, label TEXT, data_json TEXT)"
    )
    conn.commit()
    conn.close()

def load_brands():
    if not os.path.exists(BRANDS_FILE):
        return []
    with open(BRANDS_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

app = Flask(__name__)
ensure_db()

@app.route("/", methods=["GET","POST"])
def index():
    last = None
    if request.method == "POST":
        url = request.form.get("url","").strip()
        if url:
            brands = load_brands()
            result = analyze_url(url, brands)
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO results (ts, url, domain, score, label, data_json) VALUES (?, ?, ?, ?, ?, ?)",
                (result.get("timestamp"), result.get("url"), result.get("domain"),
                 result.get("risk",{}).get("score"), result.get("risk",{}).get("label"),
                 json.dumps(result, ensure_ascii=False))
            )
            conn.commit(); conn.close()
            last = result
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, ts, url, domain, score, label FROM results ORDER BY id DESC LIMIT 10")
    rows = cur.fetchall()
    conn.close()
    return render_template("index.html", title=APP_TITLE, rows=rows, last=last)

@app.route("/result/<int:rid>")
def result_detail(rid):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, ts, url, domain, score, label, data_json FROM results WHERE id=?", (rid,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return "Not found", 404
    data = json.loads(row[6])
    return render_template("detail.html", title=APP_TITLE, data=data, rid=rid)

@app.route("/history")
def history():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, ts, url, domain, score, label FROM results ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return render_template("history.html", title=APP_TITLE, rows=rows)

@app.route("/export.csv")
def export_csv():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT ts, url, domain, score, label, data_json FROM results ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    path = "export_phishguard.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp","url","domain","score","label","raw_json"])
        for r in rows:
            w.writerow(r)
    return send_file(path, as_attachment=True, download_name=path)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url","")
    if not url:
        return jsonify({"error":"url is required"}), 400
    result = analyze_url(url, load_brands())
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO results (ts, url, domain, score, label, data_json) VALUES (?, ?, ?, ?, ?, ?)",
        (result.get("timestamp"), result.get("url"), result.get("domain"),
         result.get("risk",{}).get("score"), result.get("risk",{}).get("label"),
         json.dumps(result, ensure_ascii=False))
    )
    conn.commit(); conn.close()
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
