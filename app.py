from flask import Flask, render_template, request, jsonify
from detector import analyze_url
import sqlite3
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
DB_PATH = Path(__file__).with_name("phishshield.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            status TEXT NOT NULL,
            reasons TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_scan(result):
    conn = get_db()
    conn.execute(
        """INSERT INTO scans
           (url, score, status, reasons, scanned_at)
           VALUES (?, ?, ?, ?, ?)""",
        (result["url"], result["score"], result["status"],
         "||".join(result["reasons"]),
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
@app.route("/api/scan", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL."}), 400
    result = analyze_url(url)
    save_scan(result)
    return jsonify(result)

@app.route("/history")
@app.route("/api/history")
def history():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, url, score, status, scanned_at FROM scans "
        "ORDER BY id DESC LIMIT 25"
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route("/stats")
@app.route("/api/stats")
def stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
    safe = conn.execute(
        "SELECT COUNT(*) c FROM scans WHERE status='SAFE'"
    ).fetchone()["c"]
    suspicious = conn.execute(
        "SELECT COUNT(*) c FROM scans WHERE status='SUSPICIOUS'"
    ).fetchone()["c"]
    high_risk = conn.execute(
        "SELECT COUNT(*) c FROM scans WHERE status='HIGH RISK'"
    ).fetchone()["c"]
    conn.close()
    return jsonify({
        "total": total, "safe": safe,
        "suspicious": suspicious, "high_risk": high_risk
    })

init_db()

if __name__ == "__main__":
    app.run(debug=True)

