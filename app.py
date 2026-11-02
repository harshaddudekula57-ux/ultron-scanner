from flask import Flask, request, render_template_string, send_file
import nmap, io, requests
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors

app = Flask(__name__)

VULNERS_API_KEY = "OMOJ4B5C0B68DZIRIOWXHNH0W31DNNIOZ5U73YY5VTCNC5RNE55Z71QZA5YCO1CJ"

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
        {% if results %}
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

def fetch_vulners_data(query_id):
    url = "https://vulners.com/api/v3/search/id"
    headers = {"X-Api-Key": VULNERS_API_KEY, "Content-Type": "application/json"}
    payload = {"id": query_id, "fields": ["*"]}
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        cves = []
        if data.get("result") == "OK":
            documents = data.get("data", {}).get("documents", {})
            for doc_id, doc_info in documents.items():
                if doc_id.startswith("CVE"):
                    # Robust extraction of CVSS and description
                    cvss_score = "N/A"
                    if isinstance(doc_info.get("cvss"), dict):
                        cvss_score = doc_info["cvss"].get("score", "N/A")
                    elif doc_info.get("cvss3"):
                        cvss_score = doc_info["cvss3"].get("cvss3", {}).get("baseScore", "N/A")

                    desc = doc_info.get("description", "No description available.")
                    desc = desc.replace("\n", " ").strip()
                    
                    # Extract the "Attack Type" from the description based on common keywords
                    attack = "Unknown / General Vulnerability"
                    desc_lower = desc.lower()
                    if "remote code execution" in desc_lower or "rce" in desc_lower:
                        attack = "Remote Code Execution (RCE)"
                    elif "denial of service" in desc_lower or "dos" in desc_lower:
                        attack = "Denial of Service (DoS)"
                    elif "sql injection" in desc_lower:
                        attack = "SQL Injection (SQLi)"
                    elif "cross-site scripting" in desc_lower or "xss" in desc_lower:
                        attack = "Cross-Site Scripting (XSS)"
                    elif "buffer overflow" in desc_lower or "heap overflow" in desc_lower:
                        attack = "Buffer Overflow / Memory Corruption"
                    elif "privilege escalation" in desc_lower:
                        attack = "Privilege Escalation"
                    elif "information disclosure" in desc_lower or "leak" in desc_lower:
                        attack = "Information Disclosure"
                    elif "authentication bypass" in desc_lower:
                        attack = "Authentication Bypass"

                    # Truncate description so it fits nicely in the UI
                    if len(desc) > 400:
                        desc = desc[:400] + "..."
                    
                    cves.append({
                        "id": doc_id, 
                        "cvss": cvss_score, 
                        "attack": attack,
                        "description": desc
                    })
        return cves
    except Exception as e:
        print(f"API Error: {e}")
        return []

def do_scan(target):
    nm = nmap.PortScanner()
    # Perform Nmap scan
    nm.scan(hosts=target, ports="1-1024,5000", arguments="-sT -sV")
    
    results = {}
    for host in nm.all_hosts():
        results[host] = {"state": nm[host].state(), "ports": {}}
        for proto in nm[host].all_protocols():
            for p in nm[host][proto]:
                pinfo = nm[host][proto][p]
                if pinfo["state"] != "open":
                    continue
                
                service = pinfo.get("name", "unknown")
                version = pinfo.get("version", "")
                cves = []
                
                # Fetch CVEs for the service found on the port
                if service and service != "unknown":
                    cves = fetch_vulners_data(service)
                    
                results[host]["ports"][f"{p}/{proto}"] = {
                    "state": pinfo["state"],
                    "service": service,
                    "version": version,
                    "cves": cves
                }
    return results

@app.route("/")
def index():
    return render_template_string(HTML, target="nmap.scanme.org", results=None)

@app.route("/scan")
def scan():
    target = request.args.get("target", "127.0.0.1")
    try:
        results = do_scan(target)
    except Exception as e:
        return f"<h3 style='color:red;'>Error: {str(e)}</h3>"
    return render_template_string(HTML, target=target, results=results)

@app.route("/pdf")
def pdf():
    target = request.args.get("target", "127.0.0.1")
    results = do_scan(target)
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
