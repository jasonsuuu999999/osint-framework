import asyncio
import json
import re
import shutil
import time
import dns.resolver
import whois
import httpx
import phonenumbers
from phonenumbers import geocoder, carrier
from typing import Dict, Any, List, Tuple

class SafeToolRunner:
    @staticmethod
    async def run_command(cmd_args: List[str], timeout: int = 180) -> Tuple[int, str, float]:
        start_time = time.time()
        exec_path = shutil.which(cmd_args[0])
        if not exec_path:
            return -1, f"TOOL_NOT_FOUND: 指令 '{cmd_args[0]}' 未安裝在系統 PATH 中。", 0.0

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
            exec_time = round(time.time() - start_time, 2)
            return process.returncode, stdout.decode('utf-8', errors='replace'), exec_time
        except asyncio.TimeoutError:
            return -1, f"TIMEOUT: 工具執行超過 {timeout} 秒已自動終止。", timeout
        except Exception as e:
            return -1, f"ERROR: {str(e)}", 0.0

class OSINTModules:

    # ==================== 1. 人名 / 帳號社群模組 ====================
    @staticmethod
    async def run_maigret(username: str) -> Dict[str, Any]:
        cmd = ["maigret", username, "--timeout", "10", "--no-color"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=120)
        found_accounts = []
        if code == 0:
            for line in out.splitlines():
                if "[+]" in line and "http" in line:
                    urls = re.findall(r'https?://[^\s]+', line)
                    found_accounts.extend(urls)
        return {"tool": "maigret", "return_code": code, "duration": duration, "raw_log": out, "accounts": list(set(found_accounts))}

    @staticmethod
    async def run_sherlock(username: str) -> Dict[str, Any]:
        cmd = ["sherlock", username, "--timeout", "10", "--print-found"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=120)
        found_accounts = []
        for line in out.splitlines():
            if "[+]" in line:
                urls = re.findall(r'https?://[^\s]+', line)
                found_accounts.extend(urls)
        return {"tool": "sherlock", "return_code": code, "duration": duration, "raw_log": out, "accounts": list(set(found_accounts))}

    # ==================== 2. 電子郵件模組 ====================
    @staticmethod
    async def run_holehe(email: str) -> Dict[str, Any]:
        cmd = ["holehe", email, "--only-used", "--no-color"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=120)
        discovered_platforms = []
        if code == 0:
            for line in out.splitlines():
                if "[+]" in line:
                    platform = line.replace("[+]", "").strip()
                    discovered_platforms.append(platform)
        return {"tool": "holehe", "return_code": code, "duration": duration, "raw_log": out, "platforms": list(set(discovered_platforms))}

    # ==================== 3. 電話號碼模組 ====================
    @staticmethod
    async def run_phoneinfoga(phone_number: str) -> Dict[str, Any]:
        cmd = ["phoneinfoga", "scan", "-n", phone_number]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=90)
        details = []
        try:
            parsed = phonenumbers.parse(phone_number, None)
            if phonenumbers.is_valid_number(parsed):
                country = geocoder.description_for_number(parsed, "zh-TW")
                operator = carrier.name_for_number(parsed, "zh-TW")
                if country: details.append(f"地理區域: {country}")
                if operator: details.append(f"電信業者: {operator}")
                details.append(f"國際標準格式: {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)}")
        except Exception:
            pass
        return {"tool": "phoneinfoga", "return_code": code, "duration": duration, "raw_log": out, "details": details}

    # ==================== 4. 網域、WAF、HTTP 探測與資產模組 ====================
    @staticmethod
    async def run_wafw00f(domain: str) -> Dict[str, Any]:
        """探測網站後端所屬 WAF 防護 (Cloudflare, AWS WAF 等)"""
        cmd = ["wafw00f", domain]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=60)
        wafs = []
        for line in out.splitlines():
            if "is behind" in line or "behind" in line:
                wafs.append(line.strip())
        return {"tool": "wafw00f", "return_code": code, "duration": duration, "raw_log": out, "wafs": wafs}

    @staticmethod
    async def run_httpx_probe(domain: str) -> Dict[str, Any]:
        """HTTP 指紋探測 (優先使用 httpx / httpx-toolkit CLI，無則原生 fallback)"""
        exec_name = "httpx" if shutil.which("httpx") else ("httpx-toolkit" if shutil.which("httpx-toolkit") else None)
        http_results = []
        
        if exec_name:
            cmd = [exec_name, "-u", domain, "-title", "-status-code", "-tech-detect", "-silent"]
            code, out, duration = await SafeToolRunner.run_command(cmd, timeout=60)
            for line in out.splitlines():
                if line.strip():
                    http_results.append(line.strip())
            return {"tool": "httpx", "return_code": code, "duration": duration, "raw_log": out, "results": http_results}
        else:
            # 原生 Python HTTP 探測 fallback
            start = time.time()
            raw_log = ""
            for scheme in ["https", "http"]:
                try:
                    async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, verify=False) as client:
                        resp = await client.get(f"{scheme}://{domain}", headers={"User-Agent": "Mozilla/5.0"})
                        title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
                        title = title_match.group(1).strip() if title_match else "No Title"
                        server = resp.headers.get("Server", "Unknown")
                        res_str = f"[{scheme.upper()}] Status: {resp.status_code} | Title: {title} | Server: {server}"
                        http_results.append(res_str)
                        raw_log += f"{res_str}\n"
                        break
                except Exception as e:
                    raw_log += f"[{scheme.upper()}] 連線失敗: {str(e)}\n"
            return {"tool": "httpx", "return_code": 0, "duration": round(time.time() - start, 2), "raw_log": raw_log, "results": http_results}

    @staticmethod
    async def run_theharvester(domain: str) -> Dict[str, Any]:
        cmd = ["theHarvester", "-d", domain, "-b", "certspotter,crtsh,dnsdumpster", "-l", "100"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=150)
        return {"tool": "theHarvester", "return_code": code, "duration": duration, "raw_log": out}

    @staticmethod
    async def run_amass(domain: str) -> Dict[str, Any]:
        cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", "3"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=180)
        subdomains = []
        if code == 0:
            for line in out.splitlines():
                line_str = line.strip()
                if domain in line_str and not " " in line_str:
                    subdomains.append(line_str)
        return {"tool": "amass", "return_code": code, "duration": duration, "raw_log": out, "subdomains": list(set(subdomains))}

    @staticmethod
    async def run_sublist3r(domain: str) -> Dict[str, Any]:
        cmd = ["sublist3r", "-d", domain, "-n"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=120)
        subdomains = []
        for line in out.splitlines():
            line_str = line.strip()
            if domain in line_str and not line_str.startswith("[-]"):
                subdomains.append(line_str)
        return {"tool": "sublist3r", "return_code": code, "duration": duration, "raw_log": out, "subdomains": list(set(subdomains))}

    @staticmethod
    async def run_dnsrecon(domain: str) -> Dict[str, Any]:
        cmd = ["dnsrecon", "-d", domain, "-t", "std"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=90)
        records = []
        for line in out.splitlines():
            if "[*]" in line and any(k in line for k in [" A ", " AAAA ", " MX ", " NS ", " TXT "]):
                records.append(line.replace("[*]", "").strip())
        return {"tool": "dnsrecon", "return_code": code, "duration": duration, "raw_log": out, "records": records}

    @staticmethod
    async def run_whatweb(domain: str) -> Dict[str, Any]:
        cmd = ["whatweb", domain, "--color=never", "--log-brief=/dev/stdout"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=60)
        tech_stack = []
        for line in out.splitlines():
            if domain in line and "[" in line:
                tech_stack.append(line.strip())
        return {"tool": "whatweb", "return_code": code, "duration": duration, "raw_log": out, "tech_stack": tech_stack}

    @staticmethod
    async def run_nmap_quick(target: str) -> Dict[str, Any]:
        cmd = ["nmap", "-F", "-Pn", "--open", "-sT", target]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=120)
        open_ports = []
        for line in out.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
        return {"tool": "nmap", "return_code": code, "duration": duration, "raw_log": out, "open_ports": open_ports}

    # ==================== 5. 原生保底高速探測引擎 ====================
    @staticmethod
    async def run_native_recon(target: str, target_type: str) -> Dict[str, Any]:
        start_time = time.time()
        results = []

        if target_type == "DOMAIN":
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    res = await client.get(f"https://crt.sh/?q=%25.{target}&output=json")
                    if res.status_code == 200:
                        for item in res.json()[:25]:
                            name = item.get("name_value", "").strip().replace("*.", "")
                            for sub in name.split("\n"):
                                if sub and sub not in results:
                                    results.append(f"子網域(crt.sh): {sub}")
            except Exception:
                pass

            for rtype in ["A", "MX", "TXT", "NS"]:
                try:
                    answers = dns.resolver.resolve(target, rtype)
                    for rdata in answers:
                        results.append(f"DNS {rtype}: {rdata.to_text().rstrip('.')}")
                except Exception:
                    continue

            try:
                w = whois.whois(target)
                if w.registrar: results.append(f"註冊商: {w.registrar}")
                if w.creation_date:
                    d = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    results.append(f"創立時間: {str(d).split()[0]}")
            except Exception:
                pass

        elif target_type == "PERSON":
            platforms = [
                ("GitHub", f"https://github.com/{target}"),
                ("Twitter/X", f"https://x.com/{target}"),
                ("Reddit", f"https://www.reddit.com/user/{target}"),
                ("Medium", f"https://medium.com/@{target}"),
                ("V2EX", f"https://www.v2ex.com/member/{target}")
            ]
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                for name, url in platforms:
                    try:
                        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                        if resp.status_code == 200:
                            results.append(f"社群足跡: {name} ({url})")
                    except Exception:
                        continue

        elif target_type == "EMAIL":
            domain = target.split("@")[-1]
            try:
                for rdata in dns.resolver.resolve(domain, "MX"):
                    results.append(f"Mail Server: {rdata.exchange.to_text().rstrip('.')}")
            except Exception:
                pass

        return {
            "tool": "native_engine",
            "duration": round(time.time() - start_time, 2),
            "results": results
        }
