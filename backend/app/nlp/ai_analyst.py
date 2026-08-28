import os
import traceback
from pathlib import Path
from typing import Optional, List
from dotenv import load_dotenv

ENV_PATH = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

class AIAnalyst:
    """Automated AI Dossier Summarizer and Correlation Engine."""
    
    @staticmethod
    async def generate_dossier_summary(target: str, target_type: str, entities_summary: List[str]) -> str:
        """
        Generates structured threat intelligence insights using Gemini / OpenAI.
        """
        load_dotenv(dotenv_path=ENV_PATH, override=True)
        g_key = os.getenv("GEMINI_API_KEY", "").strip()
        o_key = os.getenv("OPENAI_API_KEY", "").strip()

        if not g_key and not o_key:
            return "⚠️ Neither GEMINI_API_KEY nor OPENAI_API_KEY is configured. Skipping automated AI dossier generation."

        data_text = "\n".join(entities_summary) if entities_summary else "No additional assets or entities discovered."

        prompt = f"""
You are an expert senior OSINT threat analyst. Below is the multi-source intelligence dataset gathered for the target "{target}" (Type: {target_type}):

{data_text}

Please provide a structured, professional intelligence assessment report in English:
1. 【Target Overview and Footprint Analysis】:Assess the target's main digital activity areas, asset breadth, and exposure.
2. 【Key Related Entities】：Conduct in-depth analysis of the correlation between names, domains, social media groups, email addresses, and open service ports.
3. 【False Alarm Filtering Suggestions】：Analyze potential false alarms related to individuals with the same name, general-purpose CDNs, or third-party hosting.
4. 【Further Investigative Steps Suggestions】：Provide investigators with three of the most valuable and feasible follow-up entry points.
"""
        error_details = []

        # 1. Primary: Google Gemini with dynamic model resolution
        if g_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=g_key)

                candidate_models = [
                    "gemini-3.6-flash",
                    "gemini-3.6-pro",
                    "gemini-3-flash",
                    "gemini-2.0-flash",
                    "gemini-1.5-flash"
                ]

                available_models = []
                try:
                    for m in genai.list_models():
                        if 'generateContent' in m.supported_generation_methods:
                            available_models.append(m.name.replace("models/", ""))
                except Exception as list_err:
                    error_details.append(f"ListModels lookup bypassed: {str(list_err)}")

                models_to_run = [m for m in candidate_models if m in available_models] or candidate_models

                for model_name in models_to_run:
                    try:
                        model = genai.GenerativeModel(model_name)
                        response = model.generate_content(prompt)
                        if response and response.text:
                            return response.text
                    except Exception as me:
                        error_details.append(f"Gemini({model_name}): {str(me)}")
                        continue

            except Exception as ge:
                error_details.append(f"Gemini initialization error: {str(ge)}")

        # 2. Fallback: OpenAI
        if o_key:
            try:
                from openai import AsyncOpenAI
                client = AsyncOpenAI(api_key=o_key)
                completion = await client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a professional senior OSINT intelligence analyst."},
                        {"role": "user", "content": prompt}
                    ]
                )
                return completion.choices[0].message.content
            except Exception as oe:
                error_details.append(f"OpenAI: {str(oe)}")

        return f"⚠️ AI summarization failed. Detailed diagnostics:\n" + "\n".join(error_details)
