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
            return "⚠️ 未配置 GEMINI_API_KEY 或 OPENAI_API_KEY，請至 backend/.env 設定。"

        data_text = "\n".join(entities_summary) if entities_summary else "未探測到額外關聯實體"

        prompt = f"""
你是一名資深的 OSINT 情報分析專家。以下是針對目標「{target}」（類型：{target_type}）由多項 Kali/開源工具探測到的情報數據：

{data_text}

請根據以上數據，使用繁體中文提供一份結構化的情報調查報告：
1. 【目標概況與足跡研判】：主要活動領域、資產廣度與風險評估。
2. 【關鍵關聯實體】：分析人名、網域、社群、郵箱之間的關聯度。
3. 【誤報過濾建議】：同名同姓或泛用資產過濾提示。
4. 【下一步深挖建議】：後續切入點與調查建議。
"""
        error_details = []

        # 1. 優先使用 Google Gemini (適配最新模型)
        if g_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=g_key)

                # 最新主流模型清單優先嘗試
                candidate_models = [
                    "gemini-3.6-flash",
                    "gemini-3.6-pro",
                    "gemini-3-flash",
                    "gemini-2.0-flash",
                    "gemini-1.5-flash"
                ]

                # 動態獲取帳號支援的所有模型
                available_models = []
                try:
                    for m in genai.list_models():
                        if 'generateContent' in m.supported_generation_methods:
                            # 移除 'models/' 前綴以利統一比對
                            clean_name = m.name.replace("models/", "")
                            available_models.append(clean_name)
                except Exception as list_err:
                    error_details.append(f"ListModels 查詢略過: {str(list_err)}")

                # 建立嘗試順序：優先候選 -> 動態清單中的其他模型
                models_to_run = [m for m in candidate_models if m in available_models]
                if not models_to_run:
                    models_to_run = candidate_models + available_models

                # 執行生成
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
                error_details.append(f"Gemini 初始化異常: {str(ge)}")

        # 2. 備援使用 OpenAI
        if o_key:
            try:
                from openai import AsyncOpenAI
                client = AsyncOpenAI(api_key=o_key)
                completion = await client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "你是一名資深 OSINT 情報分析師。"},
                        {"role": "user", "content": prompt}
                    ]
                )
                return completion.choices[0].message.content
            except Exception as oe:
                error_details.append(f"OpenAI: {str(oe)}")

        return f"⚠️ AI 服務呼叫失敗。詳細除錯資訊：\n" + "\n".join(error_details)
