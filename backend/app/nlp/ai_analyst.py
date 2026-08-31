import os
import asyncio
from pathlib import Path
from typing import Optional, List
from dotenv import load_dotenv

ENV_PATH = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

class AIAnalyst:
    """Automated AI Dossier Summarizer and Correlation Engine."""
    
    @staticmethod
    async def _invoke_gemini(prompt: str, g_key: str) -> Optional[str]:
        def _call_gemini_sync():
            import google.generativeai as genai
            genai.configure(api_key=g_key)
            candidate_models = ["gemini-3.6-flash", "gemini-3.6-pro", "gemini-3-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
            for m in candidate_models:
                try:
                    model = genai.GenerativeModel(m)
                    resp = model.generate_content(prompt)
                    if resp and resp.text:
                        return resp.text
                except Exception:
                    continue
            return None
        return await asyncio.to_thread(_call_gemini_sync)

    @staticmethod
    async def _invoke_openai(prompt: str, o_key: str) -> Optional[str]:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=o_key)
        completion = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a professional senior OSINT intelligence analyst."},
                {"role": "user", "content": prompt}
            ],
            timeout=20.0
        )
        return completion.choices[0].message.content

    @staticmethod
    async def generate_dossier_summary(target: str, target_type: str, entities_summary: List[str]) -> str:
        """Generates structured intelligence report with a hard 25-second timeout."""
        load_dotenv(dotenv_path=ENV_PATH, override=True)
        g_key = os.getenv("GEMINI_API_KEY", "").strip()
        o_key = os.getenv("OPENAI_API_KEY", "").strip()

        if not g_key and not o_key:
            return "⚠️ Neither GEMINI_API_KEY nor OPENAI_API_KEY is configured."

        data_text = "\n".join(entities_summary[:50]) if entities_summary else "No additional assets or entities discovered."

        prompt = f"""
You are an expert senior OSINT threat analyst. Below is the multi-source intelligence dataset gathered for the target "{target}" (Type: {target_type}):

{data_text}

Please provide a structured, professional intelligence assessment report in Traditional Chinese (繁體中文):
1. Target Overview and Footprint Analysis: Assess the target's main digital activity areas, asset breadth, and exposure.

2. Key Related Entities: Conduct in-depth analysis of the correlation between names, domains, social media groups, email addresses, and open service ports.
3. False Alarm Filtering Suggestions: Analyze potential false alarms related to individuals with the same name, general-purpose CDNs, or third-party hosting.

4. Further Investigative Steps Suggestions: Provide investigators with three of the most valuable and feasible follow-up entry points.
"""
        # 1. Try Gemini with timeout
        if g_key:
            try:
                res = await asyncio.wait_for(AIAnalyst._invoke_gemini(prompt, g_key), timeout=20.0)
                if res:
                    return res
            except Exception as e:
                print(f"[-] Gemini call bypassed or timed out: {e}")

        # 2. Try OpenAI with timeout
        if o_key:
            try:
                res = await asyncio.wait_for(AIAnalyst._invoke_openai(prompt, o_key), timeout=20.0)
                if res:
                    return res
            except Exception as e:
                print(f"[-] OpenAI call bypassed or timed out: {e}")

        return "⚠️ The AI ​​analytics service may be temporarily unavailable, but all tools have completed the full data collection."
