import asyncio
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
    """Safe asynchronous CLI command execution handler with hard timeout and process kill."""
    @staticmethod
    async def run_command(cmd_args: List[str], timeout: int = 60) -> Tuple[int, str, str, float]:
        """
        Executes a CLI command safely, terminating hung processes automatically.
        Returns: (return_code, command_str, stdout_log, duration_seconds)
        """
        start_time = time.time()
        cmd_str = " ".join(cmd_args)
        exec_path = shutil.which(cmd_args[0])
        
        if not exec_path:
            return -1, cmd_str, f"TOOL_NOT_FOUND: Binary '{cmd_args[0]}' is not installed in the system PATH.", 0.0

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
            exec_time = round(time.time() - start_time, 2)
            return process.returncode, cmd_str, stdout.decode('utf-8', errors='replace'), exec_time
        except asyncio.TimeoutError:
            if process:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
            exec_time = round(time.time() - start_time, 2)
            return -1, cmd_str, f"TIMEOUT: Command exceeded maximum runtime limit ({timeout}s) and was terminated.", exec_time
        except Exception as e:
            if process:
                try:
                    process.kill()
                except Exception:
                    pass
            exec_time = round(time.time() - start_time, 2)
            return -1, cmd_str, f"EXECUTION_ERROR: {str(e)}", exec_time

class OSINTModules:
    """OSINT multi-source recon and CLI probing modules."""

    # ==================== 1. Identity & Username Modules ====================
    @staticmethod
    async def run_maigret(username: str) -> Dict[str, Any]:
        """Runs Maigret for deep username profiling across social platforms."""
        cmd = ["maigret", username, "--timeout", "5", "--no-color"]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=45)
        found_accounts = []
        if code == 0:
            for line in out.splitlines():
                if "[+]" in line and "http" in line:
                    urls = re.findall(r'https?://[^\s]+', line)
                    found_accounts.extend(urls)
        return {
            "tool": "maigret",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "accounts": list(set(found_accounts))
        }

    @staticmethod
    async def run_sherlock(username: str) -> Dict[str, Any]:
        """Runs Sherlock to search social media accounts by username."""
        cmd = ["sherlock", username, "--timeout", "5", "--print-found"]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=45)
        found_accounts = []
        for line in out.splitlines():
            if "[+]" in line:
                urls = re.findall(r'https?://[^\s]+', line)
                found_accounts.extend(urls)
        return {
            "tool": "sherlock",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "accounts": list(set(found_accounts))
        }

    # ==================== 2. Email Reconnaissance ====================
    @staticmethod
    async def run_holehe(email: str) -> Dict[str, Any]:
        """Runs Holehe to check email account registrations across 120+ platforms."""
        cmd = ["holehe", email, "--only-used", "--no-color"]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=40)
        discovered_platforms = []
        if code == 0:
            for line in out.splitlines():
                if "[+]" in line:
                    platform = line.replace("[+]", "").strip()
                    discovered_platforms.append(platform)
        return {
            "tool": "holehe",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "platforms": list(set(discovered_platforms))
        }

    # ==================== 3. Phone Number Intelligence ====================
    @staticmethod
    async def run_phoneinfoga(phone_number: str) -> Dict[str, Any]:
        """Runs PhoneInfoga with native libphonenumber fallback."""
        cmd = ["phoneinfoga", "scan", "-n", phone_number]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=30)
        details = []
        try:
            parsed = phonenumbers.parse(phone_number, None)
            if phonenumbers.is_valid_number(parsed):
                c_name = geocoder.description_for_number(parsed, "en")
                carrier_name = carrier.name_for_number(parsed, "en")
                if c_name: details.append(f"Region/Location: {c_name}")
                if carrier_name: details.append(f"Telecom Carrier: {carrier_name}")
                details.append(f"E.164 Format: {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)}")
        except Exception:
            pass
        return {
            "tool": "phoneinfoga",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "details": details
        }

    # ==================== 4. Domain & Infrastructure Probing ====================
    @staticmethod
    async def run_theharvester(domain: str) -> Dict[str, Any]:
        """Runs theHarvester with fast and lightweight OSINT sources."""
        sources = "hackertarget,otx,rapiddns,crtsh,duckduckgo"
        cmd = ["theHarvester", "-d", domain, "-b", sources, "-l", "100"]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=50)
        
        discovered_hosts = []
        discovered_emails = []

        for line in out.splitlines():
            line_clean = line.strip()
            if domain in line_clean and not " " in line_clean and not line_clean.startswith("[*]"):
                discovered_hosts.append(line_clean)
            if "@" in line_clean and not line_clean.startswith("["):
                emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', line_clean)
                discovered_emails.extend(emails)

        return {
            "tool": "theHarvester",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "hosts": list(set(discovered_hosts)),
            "emails": list(set(discovered_emails))
        }

    @staticmethod
    async def run_wafw00f(domain: str) -> Dict[str, Any]:
        """Runs Wafw00f to identify Web Application Firewalls protecting the target."""
        cmd = ["wafw00f", domain]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=30)
        wafs = []
        for line in out.splitlines():
            if "is behind" in line or "behind" in line:
                wafs.append(line.strip())
        return {
            "tool": "wafw00f",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "wafs": wafs
        }

    @staticmethod
    async def run_httpx_probe(domain: str) -> Dict[str, Any]:
        """Performs HTTP/HTTPS technology probing and status code discovery."""
        exec_name = "httpx" if shutil.which("httpx") else ("httpx-toolkit" if shutil.which("httpx-toolkit") else None)
        http_results = []
        
        if exec_name:
            cmd = [exec_name, "-u", domain, "-title", "-status-code", "-tech-detect", "-silent", "-timeout", "5"]
            code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=30)
            for line in out.splitlines():
                if line.strip():
                    http_results.append(line.strip())
            return {
                "tool": "httpx",
                "command": cmd_str,
                "return_code": code,
                "duration": duration,
                "raw_log": out,
                "results": http_results
            }
        else:
            start = time.time()
            raw_log = ""
            for scheme in ["https", "http"]:
                try:
                    async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=False) as client:
                        resp = await client.get(f"{scheme}://{domain}", headers={"User-Agent": "Mozilla/5.0"})
                        title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
                        title = title_match.group(1).strip() if title_match else "No Title"
                        server = resp.headers.get("Server", "Unknown")
                        res_str = f"[{scheme.upper()}] Status: {resp.status_code} | Title: {title} | Server: {server}"
                        http_results.append(res_str)
                        raw_log += f"{res_str}\n"
                        break
                except Exception as e:
                    raw_log += f"[{scheme.upper()}] Probe failed: {str(e)}\n"
            return {
                "tool": "httpx",
                "command": f"python-httpx GET {domain}",
                "return_code": 0,
                "duration": round(time.time() - start, 2),
                "raw_log": raw_log,
                "results": http_results
            }

    @staticmethod
    async def run_amass(domain: str) -> Dict[str, Any]:
        """Runs OWASP Amass in passive mode with strict 45s timeout."""
        cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=45)
        subdomains = []
        if code == 0:
            for line in out.splitlines():
                line_str = line.strip()
                if domain in line_str and not " " in line_str:
                    subdomains.append(line_str)
        return {
            "tool": "amass",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "subdomains": list(set(subdomains))
        }

    @staticmethod
    async def run_sublist3r(domain: str) -> Dict[str, Any]:
        """Runs Sublist3r passive search engine crawler."""
        cmd = ["sublist3r", "-d", domain, "-n", "-t", "5"]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=40)
        subdomains = []
        for line in out.splitlines():
            line_str = line.strip()
            if domain in line_str and not line_str.startswith("[-]"):
                subdomains.append(line_str)
        return {
            "tool": "sublist3r",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "subdomains": list(set(subdomains))
        }

    @staticmethod
    async def run_dnsrecon(domain: str) -> Dict[str, Any]:
        """Runs DNSRecon standard enumeration."""
        cmd = ["dnsrecon", "-d", domain, "-t", "std", "--lifetime", "2"]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=30)
        records = []
        for line in out.splitlines():
            if "[*]" in line and any(k in line for k in [" A ", " AAAA ", " MX ", " NS ", " TXT "]):
                records.append(line.replace("[*]", "").strip())
        return {
            "tool": "dnsrecon",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "records": records
        }

    @staticmethod
    async def run_whatweb(domain: str) -> Dict[str, Any]:
        """Runs WhatWeb for CMS and web framework identification."""
        cmd = ["whatweb", domain, "--color=never", "--log-brief=/dev/stdout", "--max-redirects=2"]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=30)
        tech_stack = []
        for line in out.splitlines():
            if domain in line and "[" in line:
                tech_stack.append(line.strip())
        return {
            "tool": "whatweb",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "tech_stack": tech_stack
        }

    @staticmethod
    async def run_nmap_quick(target: str) -> Dict[str, Any]:
        """Runs fast top-port Nmap reconnaissance (-F -Pn -sT)."""
        cmd = ["nmap", "-F", "-Pn", "--open", "-sT", "--host-timeout", "25s", target]
        code, cmd_str, out, duration = await SafeToolRunner.run_command(cmd, timeout=35)
        open_ports = []
        for line in out.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
        return {
            "tool": "nmap",
            "command": cmd_str,
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "open_ports": open_ports
        }

    # ==================== 5. Native Fallback Engine ====================
    @staticmethod
    async def run_native_recon(target: str, target_type: str) -> Dict[str, Any]:
        """Pure Python fallback for DNS, WHOIS, CT-logs, and public social endpoints."""
        start_time = time.time()
        results = []
        cmd_info = f"Native-Python-Recon-Engine [Type: {target_type}] on {target}"

        if target_type == "DOMAIN":
            # crt.sh Certificate Transparency Logs
            try:
                async with httpx.AsyncClient(timeout=6.0) as client:
                    res = await client.get(f"https://crt.sh/?q=%25.{target}&output=json")
                    if res.status_code == 200:
                        for item in res.json()[:25]:
                            name = item.get("name_value", "").strip().replace("*.", "")
                            for sub in name.split("\n"):
                                if sub and sub not in results:
                                    results.append(f"Subdomain (crt.sh): {sub}")
            except Exception:
                pass

            # DNS Standard Lookup
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            for rtype in ["A", "MX", "TXT", "NS"]:
                try:
                    answers = resolver.resolve(target, rtype)
                    for rdata in answers:
                        results.append(f"DNS {rtype}: {rdata.to_text().rstrip('.')}")
                except Exception:
                    continue

            # WHOIS Registrar Query
            try:
                w = whois.whois(target)
                if w.registrar: results.append(f"Registrar: {w.registrar}")
                if w.creation_date:
                    d = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    results.append(f"Creation Date: {str(d).split()[0]}")
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
            async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
                for name, url in platforms:
                    try:
                        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                        if resp.status_code == 200:
                            results.append(f"Social Profile: {name} ({url})")
                    except Exception:
                        continue

        elif target_type == "EMAIL":
            domain = target.split("@")[-1]
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2.0
                resolver.lifetime = 2.0
                for rdata in resolver.resolve(domain, "MX"):
                    results.append(f"Mail Server (MX): {rdata.exchange.to_text().rstrip('.')}")
            except Exception:
                pass

        return {
            "tool": "native_engine",
            "command": cmd_info,
            "return_code": 0,
            "duration": round(time.time() - start_time, 2),
            "raw_log": f"Executed native recon routines. Discovered {len(results)} items.",
            "results": results
        }
