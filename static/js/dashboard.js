// ─── Fetch Live Stats Every 3 Seconds ─────────────────
function fetchStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('total_packets').textContent = data.total_packets;
            document.getElementById('threats_detected').textContent = data.threats_detected;
            document.getElementById('alerts').textContent = data.alerts;
            document.getElementById('status').textContent = data.status;
        })
        .catch(err => console.log('Error fetching stats:', err));
}

// ─── Fetch Live Threat Feed Every 5 Seconds ───────────
function fetchThreats() {
    fetch('/api/threats')
        .then(response => response.json())
        .then(data => {
            const tbody = document.getElementById('threat-feed');
            if (data.threats.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5">No threats detected yet...</td></tr>';
                return;
            }
            tbody.innerHTML = '';
            data.threats.forEach(threat => {
                const row = `
                    <tr>
                        <td>${threat.time}</td>
                        <td>${threat.source_ip}</td>
                        <td>${threat.type}</td>
                        <td class="severity-${threat.severity.toLowerCase()}">${threat.severity}</td>
                        <td>${threat.status}</td>
                    </tr>`;
                tbody.innerHTML += row;
            });
        })
        .catch(err => console.log('Error fetching threats:', err));
}

// ─── Website Monitor (Quick) ──────────────────────────
function loadWebsite() {
    const url = document.getElementById('website-url').value;
    if (!url) { alert('Please enter a URL!'); return; }

    // Pehle iframe load karo
    document.getElementById('iframe-container').style.display = 'block';
    document.getElementById('website-frame').src = url;

    // Scanning message
    document.getElementById('site-status').innerHTML = `
        <div style="padding:15px; background:#21262d; border-radius:8px;
                    border:1px solid #30363d; margin-top:15px;">
            <p style="color:#58a6ff;">🔍 Quick scanning ${url}... ⏳</p>
        </div>`;

    // Quick check — no SQLi/XSS so it's fast!
    fetch('/api/quick_check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'online') {
            const threatColor = data.threat_level.includes('High') ? '#e3b341' :
                                data.threat_level.includes('Medium') ? '#58a6ff' : '#3fb950';

            const headers = data.security_headers;
            const headerRows = Object.entries(headers).map(([key, value]) => `
                <tr>
                    <td style="padding:8px; color:#8b949e;">🛡️ ${key}</td>
                    <td style="color:${value ? '#3fb950' : '#f85149'}">
                        ${value ? 'Present ✅' : 'Missing ❌'}
                    </td>
                </tr>`).join('');

            document.getElementById('site-status').innerHTML = `
                <div style="margin-top:15px; padding:20px; background:#21262d;
                            border-radius:8px; border:1px solid #30363d;">

                    <h3 style="color:#58a6ff; margin-bottom:15px;">
                        📊 Security Analysis — ${data.url}
                    </h3>

                    <!-- Threat Banner -->
                    <div style="padding:12px; border-radius:8px; margin-bottom:15px;
                                background:${threatColor}22; border:1px solid ${threatColor};
                                text-align:center;">
                        <p style="color:${threatColor}; font-size:16px; font-weight:bold;">
                            Threat Level: ${data.threat_level}
                        </p>
                    </div>

                    <!-- Basic Info -->
                    <h4 style="color:#8b949e; margin-bottom:10px;">📡 Basic Info</h4>
                    <table style="width:100%; border-collapse:collapse; margin-bottom:15px;">
                        <tr style="background:#161b22;">
                            <td style="padding:10px; color:#8b949e;">Status</td>
                            <td style="padding:10px; color:#3fb950;">✅ Online</td>
                        </tr>
                        <tr>
                            <td style="padding:10px; color:#8b949e;">Response Time</td>
                            <td style="padding:10px; color:#c9d1d9;">⚡ ${data.response_time}ms</td>
                        </tr>
                        <tr style="background:#161b22;">
                            <td style="padding:10px; color:#8b949e;">HTTPS</td>
                            <td style="padding:10px; color:${data.https ? '#3fb950' : '#f85149'}">
                                ${data.https ? '✅ Secure Connection' : '❌ Not Secure!'}
                            </td>
                        </tr>
                    </table>

                    <!-- Security Headers -->
                    <h4 style="color:#8b949e; margin-bottom:10px;">🛡️ Security Headers</h4>
                    <table style="width:100%; border-collapse:collapse; margin-bottom:15px;">
                        ${headerRows}
                    </table>

                    <!-- Full Scan Button -->
                    <div style="text-align:center; margin-top:10px;">
                        <button onclick="window.location.href='/scanner'"
                            style="padding:10px 25px; background:#58a6ff; color:#0d1117;
                                   border:none; border-radius:8px; font-weight:bold;
                                   cursor:pointer; font-size:14px;">
                            🔍 Run Full Vulnerability Scan
                        </button>
                    </div>
                </div>`;
        } else {
            document.getElementById('site-status').innerHTML = `
                <div style="padding:15px; background:#21262d; border-radius:8px;
                            border:1px solid #f85149; margin-top:15px;">
                    <p style="color:#f85149;">❌ ${url} is Offline or unreachable!</p>
                </div>`;
            document.getElementById('iframe-container').style.display = 'none';
        }
    });
}

// ─── Run on Page Load ──────────────────────────────────
fetchStats();
fetchThreats();

// ─── Auto Refresh ──────────────────────────────────────
setInterval(fetchStats, 3000);
setInterval(fetchThreats, 5000);