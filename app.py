from flask import Flask, request, render_template_string, send_file
import nmap, io, requests
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

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
        .vuln { color: #ff4444; font-size: 0.9em; }
        .open { color: #00ff00; }
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
                    <li>Port {{ port }} : <span class="open">{{ info.state|upper }}</span> {{ info.service }} {{ info.version }}
                    {% if info.cves %}
                        <ul>
                        {% for cve in info.cves %}
                            <li class="vuln">⚠ {{ cve.id }} (CVSS: {{ cve.cvss }}) - {{ cve.title }}</li>
                        {% endfor %}
                        </ul>
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
    headers = {
        "X-Api-Key": VULNERS_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "id": query_id,
        "fields": ["*"]
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        cves = []
        if data.get("result") == "OK":
            documents = data.get("data", {}).get("documents", {})
            for doc_id, doc_info in documents.items():
                if doc_id.startswith("CVE"):
                    cvss_score = doc_info.get("cvss", {}).get("score", "N/A")
                    title = doc_info.get("title", "No title available")
                    cves.append({"id": doc_id, "cvss": cvss_score, "title": title})
        return cves
    except Exception as e:
        print(f"API Error: {e}")
        return []

def do_scan(target):
    nm = nmap.PortScanner()
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
    return render_template_string(HTML, target="127.0.0.1", results=None)

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
                story.append(Paragraph(f"  • {cve['id']} (CVSS {cve['cvss']}): {cve['title']}", styles["Normal"]))
            story.append(Spacer(1, 0.1*inch))
            
    doc.build(story)
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=f"ultron_{target}.pdf")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
