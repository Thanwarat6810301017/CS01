import glob
import re
from collections import Counter, defaultdict

log_files = sorted(glob.glob("*.log"))
if not log_files:
    print("ไม่พบไฟล์ .log ในโฟลเดอร์นี้")
    exit()

fields = []
total_lines = 0
ip_counter = Counter()
status_counter = Counter()
uri_counter = Counter()
ua_counter = Counter()
method_counter = Counter()
suspicious_hits = defaultdict(list)

# Pattern เบื้องต้นสำหรับหาความผิดปกติ (ปรับเพิ่มได้ตามเนื้อหาจริงใน Log)
patterns = {
    "SQLi / XSS / Traversal": re.compile(r"(\%27|\'|\-\-|\%23|\#|union\+select|\.\./|\.\.\\|<script>|\%3cscript)", re.I),
    "Sensitive Files / Admin": re.compile(r"(\.env|\.git|wp-admin|phpmyadmin|admin|backup|\.bak|\.sql|config|web\.config)", re.I),
    "Scanner / Bot UA": re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|curl|python-requests|zgrab)", re.I),
    "Auth / Error (401/403/500)": None
}

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
            total_lines += 1

            c_ip = row.get("c-ip", "-")
            cs_method = row.get("cs-method", "-")
            cs_uri_stem = row.get("cs-uri-stem", "-")
            cs_uri_query = row.get("cs-uri-query", "-")
            sc_status = row.get("sc-status", "-")
            cs_ua = row.get("cs(User-Agent)", "-")
            full_uri = f"{cs_uri_stem}?{cs_uri_query}" if cs_uri_query != "-" else cs_uri_stem

            ip_counter[c_ip] += 1
            status_counter[sc_status] += 1
            uri_counter[cs_uri_stem] += 1
            ua_counter[cs_ua] += 1
            method_counter[cs_method] += 1

            # ตรวจจับพฤติกรรมน่าสงสัย
            ref = f"{fname}:{line_num} | {c_ip} | {cs_method} {full_uri} | Status:{sc_status} | UA:{cs_ua}"
            if patterns["SQLi / XSS / Traversal"].search(full_uri):
                suspicious_hits["SQLi / XSS / Traversal"].append(ref)
            if patterns["Sensitive Files / Admin"].search(cs_uri_stem):
                suspicious_hits["Sensitive Files / Admin"].append(ref)
            if patterns["Scanner / Bot UA"].search(cs_ua):
                suspicious_hits["Scanner / Bot UA"].append(ref)
            if sc_status in ("401", "403", "500"):
                suspicious_hits[f"HTTP {sc_status}"].append(ref)

print(f"=== สรุปภาพรวม IIS Log ({len(log_files)} ไฟล์, {total_lines:,} บรรทัด) ===\n")

print("--- 1. Top 10 Client IPs ---")
for ip, cnt in ip_counter.most_common(10):
    print(f"  {ip:<20} : {cnt:,} requests")

print("\n--- 2. HTTP Status Codes ---")
for st, cnt in status_counter.most_common():
    print(f"  {st:<10} : {cnt:,}")

print("\n--- 3. HTTP Methods ---")
for m, cnt in method_counter.most_common():
    print(f"  {m:<10} : {cnt:,}")

print("\n--- 4. Top 15 Requested URIs ---")
for u, cnt in uri_counter.most_common(15):
    print(f"  {cnt:>6} | {u}")

print("\n--- 5. Top 10 User-Agents ---")
for ua, cnt in ua_counter.most_common(10):
    print(f"  {cnt:>6} | {ua[:80]}")

print("\n--- 6. กลุ่มพฤติกรรมต้องสงสัยที่ตรวจพบ ---")
for cat, items in suspicious_hits.items():
    print(f"\n[*] {cat} (พบทั้งหมด {len(items):,} รายการ) — ตัวอย่าง 5 บรรทัดแรก:")
    for sample in items[:5]:
        print(f"    {sample}")