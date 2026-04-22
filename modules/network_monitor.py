from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import threading

# ─── Store captured packets ────────────────────────────
packet_log = []
ip_count = {}
is_monitoring = False

# ─── Analyze Each Packet ───────────────────────────────
def analyze_packet(packet):
    global packet_log, ip_count

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0

        # Count packets per IP
        ip_count[src_ip] = ip_count.get(src_ip, 0) + 1

        # Detect suspicious activity
        threat = detect_threat(src_ip, port, ip_count[src_ip])

        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "port": port,
            "threat": threat
        }

        packet_log.append(entry)

        # Keep only last 50 packets
        if len(packet_log) > 50:
            packet_log.pop(0)

# ─── Detect Threats ────────────────────────────────────
def detect_threat(src_ip, port, count):
    # Port scan detection
    if port in [21, 22, 23, 80, 443, 3306, 8080]:
        if count > 5:
            return "Port Scan ⚠️"

    # Traffic spike / DoS detection
    if count > 50:
        return "DoS Attack 🚨"

    return "Normal ✅"

# ─── Start Monitoring ──────────────────────────────────
def start_monitoring():
    global is_monitoring
    is_monitoring = True
    sniff(prn=analyze_packet, store=False, count=0)

# ─── Get Packet Log ────────────────────────────────────
def get_packets():
    return packet_log

# ─── Get Stats ─────────────────────────────────────────
def get_stats():
    threats = [p for p in packet_log if p["threat"] != "Normal ✅"]
    return {
        "total_packets": len(packet_log),
        "threats_detected": len(threats),
        "alerts": len([t for t in threats if "🚨" in t["threat"]]),
        "status": "Monitoring... 🟢" if is_monitoring else "Not Running 🔴"
    }