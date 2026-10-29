import subprocess, shutil, time
import xml.etree.ElementTree as ET
from datetime import datetime

class NmapScanner:
    def __init__(self, target, log_cb=None):
        self.target = target.strip()
        self.log_cb = log_cb or (lambda m: print(m))
        self.start = time.time()
    def _log(self, m): self.log_cb(f"[*] {m}")
    def run(self, profile="fast"):
        if not shutil.which("nmap"):
            return {"error":"nmap not installed","hosts":[],"cves":[],"duration":0}
        if profile=="full":
            args=["nmap","-sV","--script","vulners","-Pn","-T4","--open","-oX","-",self.target]; budget=300
            self._log("Profile: FULL")
        else:
            args=["nmap","-sS","-F","-sV","--script","vulners","--script-args","mincvss=7.0","-Pn","-T4","--max-rtt-timeout","300ms","--max-retries","1","-n","--open","-oX","-",self.target]
            budget=45; self._log("Profile: FAST")
        self._log("Running: "+" ".join(args))
        try:
            proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try: out,err=proc.communicate(timeout=budget)
            except subprocess.TimeoutExpired:
                proc.kill(); out,err=proc.communicate()
                return {"error":f"timeout {budget}s","hosts":[],"cves":[],"duration":round(time.time()-self.start,1)}
        except FileNotFoundError:
            return {"error":"nmap not found","hosts":[],"cves":[],"duration":0}
        hosts,cves=self._parse(out); dur=round(time.time()-self.start,1)
        self._log(f"Done: {len(hosts)} host(s), {len(cves)} CVE(s) in {dur}s")
        return {"hosts":hosts,"cves":cves,"duration":dur,"error":None}
    def _parse(self,xml_output):
        hosts,cves=[],[]
        try:
            root=ET.fromstring(xml_output)
            for host in root.findall("host"):
                st=host.find("status")
                if st is not None and st.get("state")!="up": continue
                addr=host.find("address"); ip=addr.get("addr") if addr is not None else "unknown"
                ports=[]
                for p in host.findall(".//port"):
                    state=p.find("state")
                    if state is None or state.get("state")!="open": continue
                    svc=p.find("service")
                    pd={"port":int(p.get("port")),"protocol":p.get("protocol","tcp"),"service":(svc.get("name","?") if svc is not None else "?"),"product":(svc.get("product","") if svc is not None else ""),"version":(svc.get("version","") if svc is not None else "")}
                    ports.append(pd)
                    for s in p.findall("script"):
                        if s.get("id")=="vulners":
                            for line in s.get("output","").split("\n"):
                                line=line.strip()
                                if line.startswith("CVE-"):
                                    parts=line.split()
                                    if len(parts)>=3:
                                        cvss=parts[1]
                                        cves.append({"cve":parts[0],"cvss":float(cvss) if cvss.replace('.','').isdigit() else 0.0,"link":parts[2] if len(parts)>2 else "","port":pd["port"],"service":pd["service"]})
                hosts.append({"ip":ip,"ports":ports})
        except ET.ParseError as e: self._log(f"XML error: {e}")
        return hosts,cves
    def analyze(self,result):
        cves=result.get("cves",[]); cves.sort(key=lambda x:x["cvss"],reverse=True)
        cr=sum(1 for c in cves if c["cvss"]>=9.0)
        hi=sum(1 for c in cves if 7.0<=c["cvss"]<9.0)
        me=sum(1 for c in cves if 4.0<=c["cvss"]<7.0)
        lo=sum(1 for c in cves if c["cvss"]<4.0)
        risk="CRITICAL" if cr else "HIGH" if hi else "MEDIUM" if me else "LOW"
        return {"target":self.target,"scan_date":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"risk_level":risk,"total_cves":len(cves),"critical":cr,"high":hi,"medium":me,"low":lo,"cves":cves[:50],"hosts":result.get("hosts",[]),"duration":result.get("duration",0),"error":result.get("error")}
