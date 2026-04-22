from datetime import datetime

alerts = []
ip_port_map = {}
ip_count_map = {}

def check_rules(packet_log):
    global alerts, ip_port_map, ip_count_map

    # Reset maps
    ip_port_map = {}
    ip_count_map = {}

    for packet in packet_log:
        src_ip = packet["src_ip"]
        port = packet["port"]

        # Count packets per IP
        ip_count_map[src_ip] = ip_count_map.get(src_ip, 0) + 1

        # Track ports per IP
        if src_ip not in ip_port_map:
            ip_port_map[src_ip] = set()
        ip_port_map[src_ip].add(port)

        # Rule 1 - Port Scan (more than 3 different ports)
        if len(ip_port_map[src_ip]) > 3:
            add_alert(src_ip, "Port Scan", "High")

        # Rule 2 - DoS Attack (more than 20 packets)
        if ip_count_map[src_ip] > 20:
            add_alert(src_ip, "DoS Attack", "Critical")

        # Rule 3 - Brute Force (more than 10 packets on port 22 or 80)
        if port in [22, 80, 443] and ip_count_map[src_ip] > 10:
            add_alert(src_ip, "Brute Force Attempt", "High")

        # Rule 4 - Suspicious Ports
        if port in [4444, 1337, 31337, 9999]:
            add_alert(src_ip, "Suspicious Port Access", "Critical")

    return alerts


def add_alert(ip, alert_type, severity):
    global alerts
    # Avoid duplicates
    for a in alerts:
        if a["ip"] == ip and a["type"] == alert_type:
            return

    alerts.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "ip": ip,
        "type": alert_type,
        "severity": severity,
        "action": "Blocked" if severity == "Critical" else "Detected"
    })

    # Keep last 20 only
    if len(alerts) > 20:
        alerts.pop(0)


def get_alerts():
    return alerts