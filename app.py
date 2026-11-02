from flask import Flask, request, render_template_string, send_file
import nmap, io, requests, socket
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>ULTRON SCANNER + CVE</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; padding: 40px; }
        h1 { text-shadow: 0 0 10px #00ff00; }
        input { background: #111; color: #00ff00; border: 2px solid #00ff00; padding: 10px; font-family: inherit; }
        button, a.btn { background: #00ff00; color: #000; border: none; padding: 10px 20px; font-weight: bold; cursor: pointer; font-family: inherit; text-decoration: none; display: inline-block; margin-left: 10px; }
        button:hover, a.btn:hover { background: #00cc00; }
        .result-box { margin-top: 30px; border: 1px solid #00ff00; padding: 20px; background: #111; }
        
        .error-box { color: #ff4444; font-weight: bold; font-size: 1.2em; border: 1px solid #ff4444; padding: 15px; background: #220000; }
        
        .cve-card { background: #1a0000; border: 1px solid #ff4444; padding: 10px; margin-bottom: 10px; border-radius: 4px; }
        .cve-id { color: #ff4444; font-weight: bold; font-size: 1.1em; }
        .cvss { color: #ffaa00; font-weight: bold; margin-left: 10px; }
        .attack-type { color: #00ffff; font-weight: bold; font-size: 0.9em; margin-top: 5px; display: block; }
        .impact { color: #cccccc; font-size: 0.85em; margin-top: 5px; display: block; line-height: 1.4; }
        
        .open { color: #00ff00; font-weight: bold; }
        ul { list-style-type: none; padding: 0; margin: 5px 0; }
        li { padding: 5px 0; border-bottom: 1px solid #222; }
    </style>
</head>
<body>
    <h1>[ ULTRON SCANNER + CVE ]</h1>
    <form action="/scan" method="get">
        Target: <input name="target" value="{{ target }}" size="30">
        <button type="submit">EXECUTE</button>
    </form>
    <div class="result-box">
        {% if error %}
            <div class="error-box">[!] {{ error }}</div>
        {% elif results %}
            <h2>RESULTS: {{ target }}</h2>
            {% for host, data in results.items() %}
                <h3>Host: {{ host }} ({{ data.state|upper }})</h3>
                <ul>
                {% for port, info in data.ports.items() %}
                    <li>
                        Port {{ port }} : <span class="open">{{ info.state|upper }}</span> {{ info.service }} {{ info.version }}
                        {% if info.cves %}
                            <div style="margin-top: 10px;">
                            {% for cve in info.cves %}
                                <div class="cve-card">
                                    <span class="cve-id">{{ cve.id }}</span>
                                    <span class="cvss">CVSS: {{ cve.cvss }}</span>
                                    <span class="attack-type">⚔ Attack Type: {{ cve.attack }}</span>
                                    <span class="impact">Impact: {{ cve.description }}</span>
                                </div>
                            {% endfor %}
                            </div>
                        {% endif %}
                    </li>
                {% else %}
                    <li>No open ports found.</li>
                {% endfor %}
                </ul>
            {% endfor %}
            <br>
            <a class="btn" href="/pdf?target={{ target }}">DOWNLOAD PDF REPORT</a>
        {% else %}
            <p>System ready. Awaiting target...</p>
        {% endif %}
    </div>
</body>
</html>
"""

def validate_target(target):
    """Checks if the domain/IP actually exists before scanning"""
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False

def generate_dynamic_cve(service, version):
    """Generates a dynamic vulnerability summary based on the detected software and version"""
    if not service or service == "unknown":
        return []
        
    desc = f"The service {service} running version {version} was detected. "
    attack = "Information Gathering / Misconfiguration"
    
    # Dynamic logic based on the detected service
    if service in ["http", "https", "apache", "nginx"]:
        attack = "Web Application Attack Surface"
        desc += "This web server may be vulnerable to Cross-Site Scripting (XSS), SQL Injection (SQLi), or directory traversal if outdated. Ensure security headers and patches are up to date."
    elif service in ["ssh", "openssh"]:
        attack = "Brute Force / Information Disclosure"
        desc += "SSH is exposed. While modern versions are secure, outdated versions may allow user enumeration or Denial of Service (DoS) via malformed packets."
    elif service in ["ftp"]:
        attack = "Unauthorized Access / Data Leak"
        desc += "FTP transmits data in plaintext. If anonymous login is enabled, this could lead to unauthorized file access or data leakage."
    elif service in ["mysql", "postgresql", "mssql", "redis"]:
        attack = "Database Exploitation"
        desc += "A database port is exposed to the public. This is highly dangerous. If authentication is bypassed, attackers can exfiltrate or delete sensitive data."
    else:
        desc += "This service is exposed to the network. Ensure it is patched to the latest version and protected by a firewall."
        
    return [{
        "id": "VULN-ANALYSIS",
        "cvss": "VARIES",
        "attack": attack,
        "description": desc
    }]

def do_scan(target):
    # 1. Validate Target first
    if not validate_target(target):
        return {"error": "URL / Target is Invalid or Offline. Could not resolve hostname."}

    nm = nmap.PortScanner()
    # 2. Scan target
    try:
        nm.scan(hosts=target, ports="1-1024,5000", arguments="-sT -sV --host-timeout 30s")
    except Exception:
        return {"error": "Scan failed or timed out."}
    
    results = {}
    host_up = False
    
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            host_up = True
            results[host] = {"state": nm[host].state(), "ports": {}}
            for proto in nm[host].all_protocols():
                for p in nm[host][proto]:
                    pinfo = nm[host][proto][p]
                    if pinfo["state"] != "open":
                        continue
                    
                    service = pinfo.get("name", "unknown")
                    version = pinfo.get("version", "")
                    
                    # 3. Use dynamic logic so *every* target gets a summary
                    cves = generate_dynamic_cve(service, version)
                        
                    results[host]["ports"][f"{p}/{proto}"] = {
                        "state": pinfo["state"],
                        "service": service,
                        "version": version,
                        "cves": cves
                    }
                    
    if not host_up:
        return {"error": "Target is offline or blocked by a firewall."}
        
    return results

@app.route("/")
def index():
    return render_template_string(HTML, target="", results=None, error=None)

@app.route("/scan")
def scan():
    target = request.args.get("target", "")
    if not target:
        return render_template_string(HTML, target="", results=None, error="Please enter a target.")
        
    try:
        results = do_scan(target)
        if "error" in results:
            return render_template_string(HTML, target=target, results=None, error=results["error"])
    except Exception as e:
        return render_template_string(HTML, target=target, results=None, error=str(e))
        
    return render_template_string(HTML, target=target, results=results, error=None)

@app.route("/pdf")
def pdf():
    target = request.args.get("target", "")
    results = do_scan(target)
    if "error" in results:
        return f"<h3>Error: {results['error']}</h3>"
        
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [Paragraph(f"ULTRON Vulnerability Report: {target}", styles["Title"]), Spacer(1, 0.3*inch)]
    
    for host, data in results.items():
        story.append(Paragraph(f"Host: {host} ({data['state']})", styles["Heading2"]))
        for port, info in data["ports"].items():
            line = f"Port {port}: {info['state']} - {info['service']} {info['version']}"
            story.append(Paragraph(line, styles["Normal"]))
            for cve in info["cves"]:
                story.append(Paragraph(f"<b>{cve['id']}</b> (CVSS {cve['cvss']})", styles["Normal"]))
                story.append(Paragraph(f"<font color='#00cc00'>Attack Type: {cve['attack']}</font>", styles["Normal"]))
                story.append(Paragraph(f"<i>{cve['description']}</i>", styles["Normal"]))
                story.append(Spacer(1, 0.15*inch))
            story.append(Spacer(1, 0.1*inch))
            
    doc.build(story)
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=f"ultron_{target}.pdf")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
