from flask import Flask, render_template, jsonify, request, send_file
from modules.vuln_scanner import run_scan
from modules.secure_transfer import generate_key, encrypt_file, decrypt_file
from modules.network_monitor import start_monitoring, get_packets, get_stats
from modules.ids import check_rules, get_alerts
from datetime import datetime
import threading
import requests
import time
import io

app = Flask(__name__)
encrypted_storage = {}

# ─── Start Network Monitor in Background ──────────────
monitor_thread = threading.Thread(target=start_monitoring, daemon=True)
monitor_thread.start()

# ─── Routes ───────────────────────────────────────────
@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/logs')
def logs():
    return render_template('logs.html')

@app.route('/alerts')
def alerts():
    return render_template('alerts.html')

@app.route('/scanner')
def scanner():
    return render_template('scanner.html')

@app.route('/transfer')
def transfer():
    return render_template('transfer.html')

# ─── API Endpoints ─────────────────────────────────────
@app.route('/api/stats')
def stats():
    return jsonify(get_stats())

@app.route('/api/threats')
def get_threats():
    packets = get_packets()
    threats = [p for p in packets if p["threat"] != "Normal ✅"]
    return jsonify({"threats": [
        {
            "time": t["time"],
            "source_ip": t["src_ip"],
            "type": t["threat"],
            "severity": "High" if "⚠️" in t["threat"] else "Critical",
            "status": "Detected"
        } for t in threats
    ]})

@app.route('/api/logs')
def get_logs():
    packets = get_packets()
    return jsonify({"logs": [
        {
            "time": p["time"],
            "ip": p["src_ip"],
            "event": f"{p['protocol']} packet on port {p['port']}",
            "level": "WARNING" if p["threat"] != "Normal ✅" else "INFO"
        } for p in packets
    ]})

@app.route('/api/alerts')
def get_alerts_api():
    packets = get_packets()
    if packets:
        check_rules(packets)
    return jsonify({"alerts": get_alerts()})

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    results = run_scan(url)
    return jsonify({"results": results})

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    file_data = file.read()
    if len(file_data) > 5 * 1024 * 1024:
        return jsonify({"error": "File too large! Please use files under 5MB"}), 400
    key = generate_key()
    encrypted = encrypt_file(file_data, key)
    encrypted_storage['latest'] = encrypted
    encrypted_storage['key'] = key
    with open('logs/encrypted_file.enc', 'wb') as f:
        f.write(encrypted)
    return jsonify({
        "status": "File Encrypted Successfully ✅",
        "key": key.decode()
    })

@app.route('/api/download_encrypted')
def download_encrypted():
    return send_file(
        'logs/encrypted_file.enc',
        as_attachment=True,
        download_name='encrypted_file.enc',
        mimetype='application/octet-stream'
    )

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    key = request.form.get('key')
    if not key:
        return jsonify({"error": "No key provided"}), 400
    file = request.files['file']
    try:
        decrypted = decrypt_file(file.read(), key.encode())
        with open('logs/decrypted_file', 'wb') as f:
            f.write(decrypted)
        return jsonify({
            "status": "File Decrypted Successfully ✅",
            "preview": decrypted[:100].decode(errors='replace')
        })
    except:
        return jsonify({"error": "Invalid key or corrupted file ❌"}), 400

@app.route('/api/download_decrypted')
def download_decrypted():
    return send_file(
        'logs/decrypted_file',
        as_attachment=True,
        download_name='decrypted_file',
        mimetype='application/octet-stream'
    )

@app.route('/api/quick_check', methods=['POST'])
def quick_check():
    data = request.get_json()
    url = data.get('url')
    result = {
        "url": url,
        "status": "offline",
        "response_time": 0,
        "https": False,
        "security_headers": {},
        "threat_level": "Unknown"
    }
    try:
        start = time.time()
        response = requests.get(url, timeout=3)
        end = time.time()
        result["status"] = "online"
        result["response_time"] = round((end - start) * 1000)
        result["https"] = url.startswith("https://")
        headers = response.headers
        result["security_headers"] = {
            "X-Frame-Options": "X-Frame-Options" in headers,
            "X-XSS-Protection": "X-XSS-Protection" in headers,
            "Content-Security-Policy": "Content-Security-Policy" in headers,
        }
        score = 0
        if not result["https"]: score += 2
        missing = sum(1 for v in result["security_headers"].values() if not v)
        score += missing
        if score >= 4:
            result["threat_level"] = "High ⚠️"
        elif score >= 2:
            result["threat_level"] = "Medium 🔔"
        else:
            result["threat_level"] = "Low ✅"
    except:
        result["status"] = "offline"
    return jsonify(result)

@app.route('/api/check_site', methods=['POST'])
def check_site():
    data = request.get_json()
    url = data.get('url')
    result = {
        "url": url,
        "status": "offline",
        "response_time": 0,
        "https": False,
        "sql_vulnerable": False,
        "xss_vulnerable": False,
        "security_headers": {},
        "threat_level": "Unknown"
    }
    try:
        start = time.time()
        response = requests.get(url, timeout=3)
        end = time.time()
        result["status"] = "online"
        result["response_time"] = round((end - start) * 1000)
        result["https"] = url.startswith("https://")
        headers = response.headers
        result["security_headers"] = {
            "X-Frame-Options": "X-Frame-Options" in headers,
            "X-XSS-Protection": "X-XSS-Protection" in headers,
            "Content-Security-Policy": "Content-Security-Policy" in headers,
            "Strict-Transport-Security": "Strict-Transport-Security" in headers,
        }
        try:
            sql_response = requests.get(f"{url}?id=' OR '1'='1", timeout=2)
            if any(e in sql_response.text.lower() for e in ["sql", "mysql", "error", "warning"]):
                result["sql_vulnerable"] = True
        except:
            pass
        try:
            xss_response = requests.get(f"{url}?q=<script>alert(1)</script>", timeout=2)
            if "<script>alert(1)</script>" in xss_response.text:
                result["xss_vulnerable"] = True
        except:
            pass
        score = 0
        if not result["https"]: score += 1
        if result["sql_vulnerable"]: score += 2
        if result["xss_vulnerable"]: score += 2
        missing = sum(1 for v in result["security_headers"].values() if not v)
        score += missing
        if score >= 5:
            result["threat_level"] = "Critical 🚨"
        elif score >= 3:
            result["threat_level"] = "High ⚠️"
        elif score >= 1:
            result["threat_level"] = "Medium 🔔"
        else:
            result["threat_level"] = "Low ✅"
    except:
        result["status"] = "offline"
    return jsonify(result)

# ─── Run App ──────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)