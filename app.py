from flask import Flask, request, render_template_string
import nmap

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>ULTRON SCANNER</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; padding: 40px; }
        h1 { text-shadow: 0 0 10px #00ff00; }
        input { background: #111; color: #00ff00; border: 2px solid #00ff00; padding: 10px; font-family: inherit; font-size: 16px; }
        button { background: #00ff00; color: #000; border: none; padding: 10px 20px; font-weight: bold; cursor: pointer; font-family: inherit; }
        button:hover { background: #00cc00; }
        .result-box { margin-top: 30px; border: 1px solid #00ff00; padding: 20px; background: #111; }
        .open { color: #00ff00; font-weight: bold; }
        .closed { color: #555; }
        ul { list-style-type: none; padding: 0; }
        li { padding: 5px 0; border-bottom: 1px solid #222; }
    </style>
</head>
<body>
    <h1>[ ULTRON SCANNER ]</h1>
    <form action="/scan" method="get">
        Target: <input name="target" value="{{ target }}" size="30">
        <button type="submit">EXECUTE</button>
    </form>
    <div class="result-box">
        {% if results %}
            <h2>SCAN RESULTS FOR: {{ target }}</h2>
            {% for host, data in results.items() %}
                <h3>Host: {{ host }} (Status: {{ data.state|upper }})</h3>
                <ul>
                {% for port, state in data.ports.items() %}
                    <li>Port {{ port }} : <span class="{{ state }}">{{ state|upper }}</span></li>
                {% else %}
                    <li class="closed">No open ports found.</li>
                {% endfor %}
                </ul>
            {% endfor %}
        {% else %}
            <p>System ready. Awaiting target...</p>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML, target="127.0.0.1", results=None)

@app.route("/scan")
def scan():
    target = request.args.get("target", "127.0.0.1")
    nm = nmap.PortScanner()
    try:
        # Real nmap execution: TCP connect scan (-sT), common ports
        nm.scan(hosts=target, ports="1-1024,5000", arguments="-sT")
    except Exception as e:
        return f"<h3 style='color:red;'>Real Nmap Error: {str(e)}</h3>"
    
    results = {}
    for host in nm.all_hosts():
        results[host] = {
            "state": nm[host].state(),
            "ports": {
                f"{p}/{proto}": nm[host][proto][p]["state"]
                for proto in nm[host].all_protocols()
                for p in nm[host][proto]
            }
        }
    return render_template_string(HTML, target=target, results=results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
