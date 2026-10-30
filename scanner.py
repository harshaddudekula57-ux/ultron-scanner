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
            return {"error": "nmap binary not found in PATH", "hosts": [], "cves": [], "duration": 0}

        if profile == "full":
            args = ["nmap","-sT","-sV","--script","vulners","-Pn","-T4","--open","-oX","-",self.target]
            budget = 300
            self._log("Profile: FULL (all ports + CVE scan)")
        else:
            args = ["nmap","-sT","-F","-sV","--script","vulners",
                    "--script-args","mincvss=7.0",
                    "-Pn","-T4","--max-rtt-timeout","300ms",
                    "--max-retries","1","-n","--open","-oX","-",self.target]
            budget = 45
            self._log("Profile: FAST (top 100 ports + CVE)")

        self._log("Running: " + " ".join(args))
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            try:
                out, err = proc.communicate(timeout=budget)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                self._log(f"Nmap killed after {budget}s")
                return {"error": f"Nmap exceeded {budget}s. Target may be offline or firewalled.",
                        "hosts": [], "cves": [], "duration": round(time.time()-self.start,1)}
        except FileNotFoundError:
            return {"error": "nmap binary not found",
                    "hosts": [], "cves": [], "duration": 0}

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
                    port_data = {
                        "port": int(p.get("port")),
                        "protocol": p.get("protocol", "tcp"),
                        "service": (svc.get("name","?") if svc is not None else "?"),
                        "product": (svc.get("product","") if svc is not None else ""),
                        "version": (svc.get("version","") if svc is not None else ""),
                    }
                    ports.append(port_data)

                    for script in p.findall("script"):
                        if script.get("id") == "vulners":
                            output = script.get("output", "")
                            for line in output.split("\n"):
                                line = line.strip()
                                if line.startswith("CVE-"):
                                    parts = line.split()
                                    if len(parts) >= 3:
                                        cve_id = parts[0]
                                        cvss = parts[1]
                                        link = parts[2] if len(parts) > 2 else ""
                                        cves.append({
                                            "cve": cve_id,
                                            "cvss": float(cvss) if cvss.replace('.','').isdigit() else 0.0,
                                            "link": link,
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

        if critical > 0:
            risk = "CRITICAL"
        elif high > 0:
            risk = "HIGH"
        elif medium > 0:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return {
            "target": self.target,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk_level": risk,
            "total_cves": len(cves),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "cves": cves[:50],
            "hosts": result.get("hosts", []),
            "duration": result.get("duration", 0),
            "error": result.get("error"),
        }
