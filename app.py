from flask import Flask, request, jsonify
import nmap

app = Flask(__name__)

@app.route("/")
def index():
    return """
    <h2>ULTRON Scanner (Codespaces Edition)</h2>
    <form action="/scan" method="get">
        Target: <input name="target" value="127.0.0.1">
        <button type="submit">Scan</button>
    </form>
    <p>Note: Codespaces outbound scans may be restricted. 127.0.0.1 always works.</p>
    """

@app.route("/scan")
def scan():
    target = request.args.get("target", "127.0.0.1")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, ports="1-1024", arguments="-sT")
    except Exception as e:
        return jsonify({"error": str(e), "note": "nmap may be missing or blocked"})
    results = {}
    for host in nm.all_hosts():
        results[host] = {
            "state": nm[host].state(),
            "ports": {
                f"{p}/{proto}": nm[host][proto][p]["state"]
                for proto in nm[host].all_protocols()
                for p in nm[host][proto]
                if nm[host][proto][p]["state"] == "open"
            }
        }
    return jsonify({"target": target, "results": results})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
