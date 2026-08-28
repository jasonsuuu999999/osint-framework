import os
import traceback
from pathlib import Path
from typing import Optional, List
from dotenv import load_dotenv

ENV_PATH = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

class AIAnalyst:
    @staticmethod
    async def generate_dossier_summary(target: str, target_type: str, entities_summary: List[str]) -> str:
        load_dotenv(dotenv_path=ENV_PATH, override=True)
        g_key = os.getenv("GEMINI_API_KEY", "").strip()
        o_key = os.getenv("OPENAI_API_KEY", "").strip()

        if not g_key and not o_key:
            return "⚠️ API_KEY is not configured, please configure it in backend/.env."

        data_text = "\n".join(entities_summary) if entities_summary else "No additional associated entities were detected."

        prompt = f"""
You are a senior OSINT intelligence analyst.The following is intelligence data detected by multiple Kali/open-source tools targeting.Target： {target} ,Type：{target_type} ：

{data_text}

Please provide a structured intelligence investigation report in Traditional Chinese based on the above data:
1. [Target Overview and Footprint Analysis]: Main activity areas, asset breadth and risk assessment.
2. [Key associated entities]: Analyze the correlation between people’s names, domains, communities, and emails.
3. [False positive filtering suggestions]: filtering suggestions for people with the same name or surname or general assets.
4. [Suggestions for further digging]: Follow-up entry points and investigation suggestions.
"""
        error_details = []

        # 1. Google Gemini (compatible with the latest models).
        if g_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=g_key)

                # Try the latest mainstream models first
                candidate_models = [
                    "gemini-3.6-flash",
                    "gemini-3.6-pro",
                    "gemini-3-flash",
                    "gemini-2.0-flash",
                    "gemini-1.5-flash"
                ]

                # Dynamically retrieve all models supported by the account
                available_models = []
                try:
                    for m in genai.list_models():
                        if 'generateContent' in m.supported_generation_methods:
                            # Remove 'models/' prefix to facilitate consistent comparison
                            clean_name = m.name.replace("models/", "")
                            available_models.append(clean_name)
                except Exception as list_err:
                    error_details.append(f"ListModels Query Skip: {str(list_err)}")

                # Establish order: priority candidate -> other models in the dynamic inventory
                models_to_run = [m for m in candidate_models if m in available_models]
                if not models_to_run:
                    models_to_run = candidate_models + available_models

                # Execution generation
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
                error_details.append(f"Gemini Initialization exception: {str(ge)}")

        # 2. Backup using OpenAI
        if o_key:
            try:
                from openai import AsyncOpenAI
                client = AsyncOpenAI(api_key=o_key)
                completion = await client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a senior OSINT intelligence analyst."},
                        {"role": "user", "content": prompt}
                    ]
                )
                return completion.choices[0].message.content
            except Exception as oe:
                error_details.append(f"OpenAI: {str(oe)}")

        return f"⚠️ AI service call failed. Detailed debugging information：\n" + "\n".join(error_details)
