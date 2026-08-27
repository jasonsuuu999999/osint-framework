import re
import opencc
import pypinyin
import tldextract
import phonenumbers
from email_validator import validate_email, EmailNotValidError
from typing import Dict, Any, List

# 初始化 OpenCC 轉換器
s2t_converter = opencc.OpenCC('s2t')  # 簡體轉繁體
t2s_converter = opencc.OpenCC('t2s')  # 繁體轉簡體

class InputNormalizer:
    @staticmethod
    def identify_type(raw_input: str) -> str:
        text = raw_input.strip()
        
        # 1. Email 檢查
        try:
            validate_email(text, check_deliverability=False)
            return "EMAIL"
        except EmailNotValidError:
            pass
        
        # 2. 電話檢查 (支援國際碼 +886, +86, +1 等)
        try:
            parsed_phone = phonenumbers.parse(text, None)
            if phonenumbers.is_possible_number(parsed_phone):
                return "PHONE"
        except Exception:
            pass

        # 3. 網域檢查
        ext = tldextract.extract(text)
        if ext.domain and ext.suffix and not re.search(r'[\u4e00-\u9fa5]', text):
            # 排除純中文句子
            if "." in text and not " " in text:
                return "DOMAIN"

        # 4. 中文或英文人名/暱稱
        return "PERSON"

    @classmethod
    def expand_person_identity(cls, name: str) -> Dict[str, Any]:
        """展開人名的繁簡對照與拼音變體"""
        name_clean = name.strip()
        s_name = t2s_converter.convert(name_clean)
        t_name = s2t_converter.convert(name_clean)

        # 產生拼音變體 (漢語拼音)
        pinyin_list = pypinyin.pinyin(s_name, style=pypinyin.Style.NORMAL)
        pinyin_flat = "".join([item[0] for item in pinyin_list])
        pinyin_hyphen = "-".join([item[0] for item in pinyin_list])

        # 產生別名列表 (供 Maigret/Sherlock 探測)
        aliases = list(set([
            name_clean,
            s_name,
            t_name,
            pinyin_flat,
            pinyin_hyphen,
            f"{pinyin_flat}123",
            f"{pinyin_flat}_dev"
        ]))

        return {
            "original": name_clean,
            "simplified": s_name,
            "traditional": t_name,
            "pinyin_continuous": pinyin_flat,
            "pinyin_hyphen": pinyin_hyphen,
            "suggested_aliases": aliases
        }
