import os, uuid, queue, threading, json
from flask import Flask, render_template, request, jsonify, send_file, Response
from scanner import NmapScanner
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE, "templates"))
REPORT_DIR = os.path.join(BASE, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)
JOBS = {}

def generate_pdf(s):
    ts = s["scan_date"].replace(":","").replace(" ","_").replace("-","")
    safe = (s["target"].replace("https://","").replace("http://","")
            .replace("/","_").replace(".","_")[:40] or "target")
    fn = f"ULTRON_{safe}_{ts}.pdf"
    path = os.path.join(REPORT_DIR, fn)
    doc = SimpleDocTemplate(path, pagesize=A4,
                            rightMargin=0.7*inch, leftMargin=0.7*inch,
                            topMargin=0.7*inch, bottomMargin=0.7*inch)
    st = getSampleStyleSheet()
    story = []

    story.append(Paragraph("ULTRON",
        ParagraphStyle("T", parent=st["Heading1"], fontSize=26,
                       textColor=colors.HexColor("#CC0000"), alignment=1)))
    story.append(Paragraph("CVE SCAN REPORT (NMAP + VULNERS)",
        ParagraphStyle("S", parent=st["Normal"], fontSize=11,
                       textColor=colors.HexColor("#666"), alignment=1, spaceAfter=20)))
    story.append(HRFlowable(width="100%", thickness=3,
                            color=colors.HexColor("#CC0000")))
    story.append(Spacer(1, 20))

    rows = [["TARGET:", s["target"]],
            ["SCAN DATE:", s["scan_date"]],
            ["RISK LEVEL:", s["risk_level"]],
            ["TOTAL CVEs:", str(s["total_cves"])],
            ["SCAN DURATION:", f'{s["duration"]}s']]
    if s.get("error"):
        rows.append(["ERROR:", s["error"][:80]])
    t = Table(rows, colWidths=[1.8*inch, 5.2*inch])
    t.setStyle(TableStyle([
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),10),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    story.append(Paragraph("SEVERITY BREAKDOWN",
        ParagraphStyle("H2", parent=st["Heading2"], fontSize=14,
                       textColor=colors.HexColor("#222"))))
    st2 = Table([["CRITICAL","HIGH","MEDIUM","LOW"],
                 [str(s["critical"]), str(s["high"]),
                  str(s["medium"]), str(s["low"])]],
                colWidths=[1.8*inch]*4)
    st2.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#CC0000")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("ALIGN",(0,0),(-1,-1),"CENTER"),
        ("GRID",(0,0),(-1,-1),0.5,colors.grey),
    ]))
    story.append(st2)
    story.append(Spacer(1, 20))

    story.append(Paragraph("CVE LIST",
        ParagraphStyle("H3", parent=st["Heading2"], fontSize=14,
                       textColor=colors.HexColor("#222"))))
    if s["cves"]:
        for c in s["cves"]:
            col = ("#CC0000" if c["cvss"] >= 9.0
                   else "#FF6600" if c["cvss"] >= 7.0 else "#CCAA00")
            story.append(Paragraph(
                f'<font color="{col}"><b>[{c["cvss"]:.1f}]</b></font> '
                f'{c["cve"]} on port {c["port"]} ({c["service"]})',
                ParagraphStyle("F", parent=st["Normal"], fontSize=8, spaceAfter=4)))
    else:
        story.append(Paragraph("No CVEs detected (mincvss=7.0).",
            ParagraphStyle("N", parent=st["Normal"], fontSize=10, textColor=colors.grey)))

    doc.build(story)
    return fn

def run_scan(jid, target, profile):
    q = JOBS[jid]["queue"]
    def log(m): q.put({"type":"log","msg":m})
    try:
        sc = NmapScanner(target, log_cb=log)
        raw = sc.run(profile=profile)
        s = sc.analyze(raw)
        pdf = generate_pdf(s)
        JOBS[jid].update({"result":s, "pdf":pdf, "status":"done"})
        q.put({"type":"done", "pdf":pdf, "risk":s["risk_level"],
               "total":s["total_cves"], "critical":s["critical"],
               "high":s["high"], "medium":s["medium"], "low":s["low"],
               "duration":s["duration"], "cves":s["cves"][:10],
               "error":s.get("error")})
    except Exception as e:
        q.put({"type":"error","msg":str(e)})

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    jid = uuid.uuid4().hex[:12]
    JOBS[jid] = {"queue": queue.Queue()}
    threading.Thread(target=run_scan,
                     args=(jid, data.get("target","").strip(),
                           data.get("profile","fast")),
                     daemon=True).start()
    return jsonify({"job_id": jid})

@app.route("/stream/<jid>")
def stream(jid):
    def gen():
        q = JOBS.get(jid,{}).get("queue")
        if not q:
            return
        while True:
            try:
                m = q.get(timeout=30)
                yield f"data: {json.dumps(m)}\n\n"
                if m["type"] in ("done","error"):
                    break
            except Exception:
                break
    return Response(gen(), mimetype="text/event-stream")

@app.route("/download/<fn>")
def download(fn):
    p = os.path.join(REPORT_DIR, fn)
    if os.path.exists(p):
        return send_file(p, as_attachment=True)
    return ("Not found", 404)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
