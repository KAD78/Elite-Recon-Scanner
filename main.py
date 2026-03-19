#!/usr/bin/env python3
import asyncio, ipaddress, json, ssl, sys, socket
from datetime import datetime

# ===== CONFIG =====
TIMEOUT = 2
MAX_CONCURRENT = 120
RETRIES = 2
OUTPUT_FILE = "elite_scan.json"

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,554,8080,8000,8443,3306,3389]

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# ===== DETECTION =====
def detect_service(port, banner):
    b = banner.lower()
    if port == 554: return "RTSP"
    if "ssh" in b: return "SSH"
    if "ftp" in b: return "FTP"
    if "smtp" in b: return "SMTP"
    if "mysql" in b: return "MySQL"
    if "rdp" in b: return "RDP"
    if "nginx" in b: return "nginx"
    if "apache" in b: return "apache"
    if "http" in b: return "HTTP"
    if port == 443: return "HTTPS"
    return "Unknown"

# ===== OS DETECTION =====
def detect_os(port, banner):
    b = banner.lower()
    if "cisco" in b: return "Cisco"
    if port == 3389: return "Windows"
    if "ubuntu" in b or "linux" in b: return "Linux"
    if "ssh" in b: return "Unix-like"
    return "Unknown"

# ===== RISK ANALYSIS =====
def risk_level(port):
    risky = {21:"FTP exposed",23:"Telnet insecure",3389:"RDP exposed",554:"Camera exposed"}
    return risky.get(port, "")

# ===== DNS =====
def resolve(target):
    try:
        ip = socket.gethostbyname(target)
        print(f"[DNS] {target} → {ip}")
        return ip
    except:
        return target

# ===== PORT SCAN =====
async def scan_port(ip, port):
    for _ in range(RETRIES):
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX) if port in [443,8443] else asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)

            banner = ""

            if port in [80,8080,8000,8443,443]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()

            if port == 554:
                writer.write(b"OPTIONS rtsp://test RTSP/1.0\r\n\r\n")
                await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=TIMEOUT)
                banner = data.decode(errors="ignore")[:200] if data else ""
            except:
                pass

            writer.close()
            try: await writer.wait_closed()
            except: pass

            return (ip, port, banner)
        except:
            continue
    return None

# ===== EXPAND =====
def expand(target):
    try:
        if "/" not in target: target += "/32"
        return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
    except:
        return []

# ===== SCAN =====
async def scan(target):
    ips = expand(target)
    if not ips:
        print("[!] Invalid target")
        return []

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    results = []

    async def worker(ip, port):
        async with sem:
            await asyncio.sleep(0.001)
            return await scan_port(ip, port)

    tasks = [asyncio.create_task(worker(ip,p)) for ip in ips for p in COMMON_PORTS]

    for t in asyncio.as_completed(tasks):
        try:
            r = await t
            if r:
                results.append(r)
                show(r)
        except:
            pass

    return results

# ===== DISPLAY =====
def show(res):
    ip, port, banner = res
    svc = detect_service(port, banner)
    os_ = detect_os(port, banner)
    risk = risk_level(port)

    print(f"[+] {ip}:{port} → {svc} ({os_})")
    if risk:
        print(f"    ⚠️ Risk: {risk}")
    if banner:
        print(f"    └─ {banner.splitlines()[0]}")

# ===== WEB ANALYSIS =====
async def web_scan(ip):
    import aiohttp
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for proto in ["http","https"]:
            url = f"{proto}://{ip}"
            try:
                async with session.get(url, ssl=False) as r:
                    server = r.headers.get("Server","?")
                    cf = "Cloudflare" if "cloudflare" in server.lower() else ""
                    print(f"[WEB] {url} → {r.status} | {server} {cf}")
            except:
                pass

# ===== SAVE =====
def save(results):
    with open(OUTPUT_FILE,"w") as f:
        json.dump([
            {
                "ip":ip,
                "port":port,
                "service":detect_service(port,b),
                "os":detect_os(port,b),
                "risk":risk_level(port),
                "banner":b
            } for ip,port,b in results
        ],f,indent=4)
    print(f"\n💾 Saved → {OUTPUT_FILE}")

# ===== MAIN =====
def main():
    print("\n=== ELITE RECON MODE ===\n")

    target = resolve(sys.argv[1]) if len(sys.argv)>1 else resolve(input("Target: ").strip())

    if not target:
        print("[!] No target")
        return

    start = datetime.now()

    print("\n[+] Scanning network...\n")
    results = asyncio.run(scan(target))

    if not results:
        print("[-] No results")
        return

    ips = list(set(r[0] for r in results))

    print("\n[+] Web analysis...\n")
    asyncio.run(asyncio.gather(*(web_scan(ip) for ip in ips)))

    print("\n[+] RTSP audit...")
    for ip,port,_ in results:
        if port==554:
            print(f"[CAM] {ip}:554 detected")

    save(results)

    print(f"\n⏱ Duration: {datetime.now()-start}")
    print("\n✅ Elite scan complete\n")

if __name__=="__main__":
    main()
