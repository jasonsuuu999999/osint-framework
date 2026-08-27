import os
import google.generativeai as genai
from typing import Optional

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

class AIAnalyst:
    @staticmethod
    async def generate_dossier_summary(target: str, target_type: str, entities_summary: list) -> Optional[str]:
        """調用 Gemini 產生調查總結報告"""
        if not GEMINI_API_KEY:
            return "AI API Key 未配置，跳過 AI 情報自動彙整。"

        prompt = f"""
你是一名資深的 OSINT 情報分析專家。以下是針對目標「{target}」（類型：{target_type}）的自動化探測數據彙整：

{entities_summary}

請根據以上數據，使用繁體中文提供一份專業的情報調查報告，包含：
1. 目標總體風險與數位足跡評估
2. 關鍵實體關聯發現（人、網域、社群、郵箱的關聯性）
3. 潛在的偽冒/同名誤報過濾建議
4. 下一步深入調查建議
"""
        try:
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"AI 摘要生成失敗: {str(e)}"
