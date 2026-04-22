import requests

def scan_sql_injection(url):
    payloads = ["' OR '1'='1", "' OR 1=1--", "' DROP TABLE users--"]
    results = []

    for payload in payloads:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if any(error in response.text.lower() for error in 
                   ["sql", "mysql", "syntax", "error", "warning"]):
                results.append({
                    "type": "SQL Injection",
                    "payload": payload,
                    "status": "Vulnerable ⚠️"
                })
            else:
                results.append({
                    "type": "SQL Injection",
                    "payload": payload,
                    "status": "Safe ✅"
                })
        except:
            results.append({
                "type": "SQL Injection",
                "payload": payload,
                "status": "Unreachable ❌"
            })
    return results


def scan_xss(url):
    payloads = ["<script>alert('xss')</script>", "<img src=x onerror=alert(1)>"]
    results = []

    for payload in payloads:
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                results.append({
                    "type": "XSS",
                    "payload": payload,
                    "status": "Vulnerable ⚠️"
                })
            else:
                results.append({
                    "type": "XSS",
                    "payload": payload,
                    "status": "Safe ✅"
                })
        except:
            results.append({
                "type": "XSS",
                "payload": payload,
                "status": "Unreachable ❌"
            })
    return results


def run_scan(url):
    results = []
    results += scan_sql_injection(url)
    results += scan_xss(url)
    return results