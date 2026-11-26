import glob
from collections import Counter, defaultdict

log_files = sorted(glob.glob("*.log"))
fields = []

# เก็บข้อมูลเจาะลึกตามประเด็นความเสี่ยงที่พบเบื้องต้น
repslip_hits = []
dxxrdv_hits = []
status_404_uris = Counter()
status_404_ips = Counter()
status_500_hits = []
external_ip_hits = defaultdict(list)
query_sensitive_hits = []
command_services_hits = []
login_post_ips = Counter()

for fname in log_files:
    with open(fname, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#Fields:"):
                fields = line.replace("#Fields:", "").strip().split()
                continue
            if line.startswith("#"):
                continue
            parts = line.split()
            if not fields or len(parts) < len(fields):
                continue

            row = dict(zip(fields, parts))
            date_t = f"{row.get('date','')} {row.get('time','')}"
            c_ip = row.get("c-ip", "-")
            method = row.get("cs-method", "-")
            uri = row.get("cs-uri-stem", "-")
            query = row.get("cs-uri-query", "-")
            status = row.get("sc-status", "-")
            substatus = row.get("sc-substatus", "-")
            ua = row.get("cs(User-Agent)", "-")
            cs_user = row.get("cs-username", "-")
            ref_str = f"{fname}:{line_num} [{date_t}] IP:{c_ip} User:{cs_user} {method} {uri}?{query} -> {status}.{substatus}"

            # 1. สลิปเงินเดือน RepSlip.aspx (เสี่ยง IDOR & Sensitive Query String)
            if "RepSlip.aspx" in uri:
                repslip_hits.append(ref_str)

            # 2. DevExpress Document Viewer DXXRDV.axd (Export/Report Viewer)
            if "DXXRDV.axd" in uri and query != "-":
                dxxrdv_hits.append(ref_str)

            # 3. 404 Not Found (Enumeration / Broken Links / Missing Files)
            if status == "404":
                status_404_uris[uri] += 1
                status_404_ips[c_ip] += 1

            # 4. 500 Internal Server Error
            if status == "500":
                status_500_hits.append(ref_str)

            # 5. Public / External IPs (ไม่ใช่ 10.x, 192.168.x, 172.16-31.x, ::1, 127.0.0.1)
            if not (c_ip.startswith(("10.", "192.168.", "127.", "::1")) or 
                    (c_ip.startswith("172.") and 16 <= int(c_ip.split(".")[1]) <= 31)):
                external_ip_hits[c_ip].append(ref_str)

            # 6. Sensitive parameters in GET Query String (CWE-598)
            if method == "GET" and query != "-" and any(k in query.lower() for k in ["id=", "salary", "pass", "token", "user", "emp", "code", "period"]):
                query_sensitive_hits.append(ref_str)

            # 7. Localhost CommandServices.asmx
            if "CommandServices.asmx" in uri:
                command_services_hits.append(ref_str)

            # 8. Login POST attempts
            if "login.aspx" in uri.lower() and method == "POST":
                login_post_ips[c_ip] += 1

print("=== 1. RepSlip.aspx (สลิปเงินเดือน) ===")
print(f"พบทั้งหมด {len(repslip_hits)} รายการ (ตัวอย่าง 15 รายการ):")
for x in repslip_hits[:15]: print(" ", x)

print("\n=== 2. DXXRDV.axd (DevExpress Report Export/View) ===")
print(f"พบทั้งหมด {len(dxxrdv_hits)} รายการ (ตัวอย่าง 10 รายการ):")
for x in dxxrdv_hits[:10]: print(" ", x)

print("\n=== 3. HTTP 404 Top 15 URIs & Top 10 IPs ===")
for u, c in status_404_uris.most_common(15): print(f"  {c:>5} | {u}")
print("  --- Top IPs causing 404 ---")
for ip, c in status_404_ips.most_common(10): print(f"  {c:>5} | {ip}")

print("\n=== 4. HTTP 500 ทั้งหมด (7 รายการ) ===")
for x in status_500_hits: print(" ", x)

print("\n=== 5. Public / External IPs ที่เข้ามาในระบบ ===")
for ip, items in sorted(external_ip_hits.items(), key=lambda x: -len(x[1]))[:15]:
    print(f"  IP {ip} : {len(items)} requests | ตัวอย่าง: {items[0]}")

print("\n=== 6. GET Request ที่มี Sensitive Query Parameters ===")
print(f"พบทั้งหมด {len(query_sensitive_hits)} รายการ (ตัวอย่าง 15 รายการ):")
for x in query_sensitive_hits[:15]: print(" ", x)

print("\n=== 7. CommandServices.asmx ===")
print(f"พบทั้งหมด {len(command_services_hits)} รายการ (ตัวอย่าง 5 รายการ):")
for x in command_services_hits[:5]: print(" ", x)

print("\n=== 8. Top IPs ที่ทำ POST login.aspx ===")
for ip, c in login_post_ips.most_common(10): print(f"  {c:>5} | {ip}")