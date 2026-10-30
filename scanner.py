import subprocess, shutil, time
import xml.etree.ElementTree as ET
from datetime import datetime

class NmapScanner:
    def __init__(self, target, log_cb=None):
        self.target = target.strip()
        self.log_cb = log_cb or (lambda m: print(m))
        self.start = time.time()

    def _log(self, m):
        self.log_cb(f"[*] {m}")

    def run(self, profile="fast"):
        if not shutil.which("nmap"):
            return {"error": "nmap binary not found", "hosts": [], "cves": [], "duration": 0}

        # THE BYPASS FLAGS:
        # -sT : TCP connect (no raw sockets)
        # --unprivileged : Tells Nmap explicitly NOT to use root/admin features
        # -p : Limited to top 1000 ports to prevent cloud timeouts
        # -sV : Version detection (strictly required for vulners)
        # -T4 : Speed it up
        args = ["nmap", "-sT", "--unprivileged", "-sV", 
                "--script", "vulners", "--script-args", "mincvss=5.0",
                "-Pn", "-T4", "--open", "-oX", "-", self.target]

        self._log("Profile: UNPRIVILEGED BYPASS (TCP Connect + Top Ports)")
        self._log("Running: " + " ".join(args))
        
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                # Give it a strict 60 seconds limit so Render doesn't kill it
                out, err = proc.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                self._log("Nmap killed after 60s (Timeout)")
                return {"error": "Scan timed out. The target is likely dropping packets.",
                        "hosts": [], "cves": [], "duration": round(time.time()-self.start,1)}
        except FileNotFoundError:
            return {"error": "nmap binary not found", "hosts": [], "cves": [], "duration": 0}

        hosts, cves = self._parse(out)
        duration = round(time.time() - self.start, 1)
        self._log(f"Scan complete: {len(hosts)} host(s), {len(cves)} CVE(s) in {duration}s")
        return {"hosts": hosts, "cves": cves, "duration": duration, "error": None}

    def _parse(self, xml_output):
        hosts, cves = [], []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall("host"):
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue
                addr = host.find("address")
                ip = addr.get("addr") if addr is not None else "unknown"
                ports = []
                for p in host.findall(".//port"):
                    state = p.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    svc = p.find("service")
                    port_str = p.get("port")
                    if not port_str: continue
                    port_data = {
                        "port": int(port_str),
                        "protocol": p.get("protocol", "tcp"),
                        "service": (svc.get("name","?") if svc is not None else "?"),
                        "product": (svc.get("product","") if svc is not None else ""),
                        "version": (svc.get("version","") if svc is not None else ""),
                    }
                    ports.append(port_data)

                    for script in p.findall("script"):
                        if script.get("id") == "vulners":
                            for line in script.get("output", "").split("\n"):
                                line = line.strip()
                                if line.startswith("CVE-"):
                                    parts = line.split()
                                    if len(parts) >= 3:
                                        cve_id = parts[0]
                                        cvss = parts[1]
                                        cves.append({
                                            "cve": cve_id,
                                            "cvss": float(cvss) if cvss.replace('.','').isdigit() else 0.0,
                                            "port": port_data["port"],
                                            "service": port_data["service"],
                                        })
                hosts.append({"ip": ip, "ports": ports})
        except ET.ParseError as e:
            self._log(f"XML parse error: {e}")
        return hosts, cves

    def analyze(self, result):
        cves = result.get("cves", [])
        cves.sort(key=lambda x: x["cvss"], reverse=True)
        critical = sum(1 for c in cves if c["cvss"] >= 9.0)
        high = sum(1 for c in cves if 7.0 <= c["cvss"] < 9.0)
        medium = sum(1 for c in cves if 4.0 <= c["cvss"] < 7.0)
        low = sum(1 for c in cves if c["cvss"] < 4.0)
        risk = "CRITICAL" if critical else "HIGH" if high else "MEDIUM" if medium else "LOW"
        return {
            "target": self.target,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk_level": risk,
            "total_cves": len(cves),
            "critical": critical, "high": high, "medium": medium, "low": low,
            "cves": cves[:50],
            "hosts": result.get("hosts", []),
            "duration": result.get("duration", 0),
            "error": result.get("error"),
        }
