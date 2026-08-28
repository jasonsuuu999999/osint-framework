import os
from typing import Optional, List
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

class AIAnalyst:
    @staticmethod
    async def generate_dossier_summary(target: str, target_type: str, entities_summary: List[str]) -> Optional[str]:
        """優先使用 Gemini，若無則降級使用 OpenAI"""
        if not GEMINI_API_KEY and not OPENAI_API_KEY:
            return "⚠️ 未配置 GEMINI_API_KEY 或 OPENAI_API_KEY，跳過 AI 情報自動彙整。"

        data_text = "\n".join(entities_summary) if entities_summary else "未探測到額外關聯實體"

        prompt = f"""
你是一名資深的 OSINT 情報分析專家。以下是針對目標「{target}」（類型：{target_type}）的自動化探測數據彙整：

{data_text}

請根據以上數據，使用繁體中文提供一份專業的情報調查摘要報告：
1. 目標總體風險與數位足跡評估
2. 關鍵實體關聯發現（人、網域、社群、郵箱的關聯性）
3. 潛在的偽冒/同名誤報過濾建議
4. 下一步深入調查建議
"""
        # 1. 優先使用 Gemini
        if GEMINI_API_KEY:
            try:
                import google.generativeai as genai
                genai.configure(api_key=GEMINI_API_KEY)
                model = genai.GenerativeModel("gemini-1.5-flash")
                response = model.generate_content(prompt)
                return response.text
            except Exception as e:
                print(f"Gemini 生成失敗: {e}")

        # 2. 備援使用 OpenAI
        if OPENAI_API_KEY:
            try:
                from openai import AsyncOpenAI
                client = AsyncOpenAI(api_key=OPENAI_API_KEY)
                completion = await client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "你是一名資深 OSINT 資安情資分析師。"},
                        {"role": "user", "content": prompt}
                    ]
                )
                return completion.choices[0].message.content
            except Exception as e:
                return f"AI 摘要生成失敗: {str(e)}"

        return "AI 分析服務暫時無法使用。"
