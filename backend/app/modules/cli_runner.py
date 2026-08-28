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
        # 原生 Python libphonenumber 解析作為保底與補充
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

    # ==================== 4. 網域與資產模組 ====================
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
    async def run_dnsrecon(domain: str) -> Dict[str, Any]:
        cmd = ["dnsrecon", "-d", domain, "-t", "std"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=90)
        records = []
        for line in out.splitlines():
            if "[*]" in line and any(k in line for k in [" A ", " AAAA ", " MX ", " NS ", " TXT "]):
                records.append(line.replace("[*]", "").strip())
        return {"tool": "dnsrecon", "return_code": code, "duration": duration, "raw_log": out, "records": records}

    @staticmethod
    async def run_native_recon(target: str, target_type: str) -> Dict[str, Any]:
        """純 Python 高速原生探測引擎（免外部 CLI，提供 100% 可用率保底）"""
        start_time = time.time()
        results = []

        if target_type == "DOMAIN":
            # 1. crt.sh 憑證透明度日誌
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

            # 2. DNS 記錄
            for rtype in ["A", "MX", "TXT", "NS"]:
                try:
                    answers = dns.resolver.resolve(target, rtype)
                    for rdata in answers:
                        results.append(f"DNS {rtype}: {rdata.to_text().rstrip('.')}")
                except Exception:
                    continue

            # 3. WHOIS
            try:
                w = whois.whois(target)
                if w.registrar: results.append(f"註冊商: {w.registrar}")
                if w.creation_date:
                    d = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    results.append(f"創立時間: {str(d).split()[0]}")
            except Exception:
                pass

        elif target_type == "PERSON":
            # 跨平台快速探測
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
            # MX 記錄與 Gravatar
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
