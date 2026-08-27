import asyncio
import json
import time
import shutil
from typing import Dict, Any, List, Tuple

class SafeToolRunner:
    @staticmethod
    async def run_command(cmd_args: List[str], timeout: int = 300) -> Tuple[int, str, float]:
        """安全執行 CLI 指令 (不使用 shell=True)"""
        start_time = time.time()
        
        # 檢查指令主程式是否存在
        exec_path = shutil.which(cmd_args[0])
        if not exec_path:
            return -1, f"Error: Tool '{cmd_args[0]}' is not installed in the system PATH.", 0.0

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
            exec_time = time.time() - start_time
            return process.returncode, stdout.decode('utf-8', errors='replace'), round(exec_time, 2)
        except asyncio.TimeoutError:
            return -1, f"Error: Command timed out after {timeout} seconds.", timeout
        except Exception as e:
            return -1, f"Error executing tool: {str(e)}", 0.0

class OSINTModules:
    @staticmethod
    async def run_holehe(email: str) -> Dict[str, Any]:
        """執行 Holehe 探測 Email 註冊狀況"""
        # holehe test@example.com --only-used --no-color
        cmd = ["holehe", email, "--only-used", "--no-color"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=120)
        
        discovered_platforms = []
        for line in out.splitlines():
            if "[+]" in line:
                platform = line.replace("[+]", "").strip()
                discovered_platforms.append(platform)

        return {
            "tool": "holehe",
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "platforms_found": discovered_platforms
        }

    @staticmethod
    async def run_maigret(username: str) -> Dict[str, Any]:
        """執行 Maigret 探測帳號社群足跡"""
        # maigret <username> --json /dev/stdout --timeout 10
        cmd = ["maigret", username, "--timeout", "10", "--no-color"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=180)
        
        found_accounts = []
        for line in out.splitlines():
            if "[+]" in line and "http" in line:
                found_accounts.append(line.strip())

        return {
            "tool": "maigret",
            "return_code": code,
            "duration": duration,
            "raw_log": out,
            "accounts_found": found_accounts
        }

    @staticmethod
    async def run_theharvester(domain: str) -> Dict[str, Any]:
        """執行 theHarvester 蒐集域名資產"""
        cmd = ["theHarvester", "-d", domain, "-b", "certspotter,crtsh,dnsdumpster", "-l", "100"]
        code, out, duration = await SafeToolRunner.run_command(cmd, timeout=180)
        
        return {
            "tool": "theHarvester",
            "return_code": code,
            "duration": duration,
            "raw_log": out
        }
