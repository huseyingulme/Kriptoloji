from .base import TextEncryptionAlgorithm
from typing import Union


class VigenereCipher(TextEncryptionAlgorithm):
    def __init__(self):
        super().__init__("Vigenere")
        self.required_params = ["keyword"]

    def _prepare_keyword(self, keyword: str, length: int) -> str:
        k = "".join(c.upper() for c in keyword if c.isalpha())
        if len(k) == 0:
            raise ValueError("Anahtar kelime en az bir harf içermelidir")
        return (k * ((length // len(k)) + 1))[:length]

    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: keyword")
        keyword = str(kwargs["keyword"])
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        alpha_count = sum(1 for c in text if c.isalpha())
        if alpha_count == 0:
            return text
        prepared_keyword = self._prepare_keyword(keyword, alpha_count)
        result = []
        key_index = 0
        for ch in text:
            if ch.isalpha():
                is_upper = ch.isupper()
                base = ord("A") if is_upper else ord("a")
                p = ord(ch.upper()) - ord("A")
                k = ord(prepared_keyword[key_index]) - ord("A")
                c_val = (p + k) % 26
                enc = chr(c_val + base)
                result.append(enc)
                key_index += 1
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: keyword")
        keyword = str(kwargs["keyword"])
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        alpha_count = sum(1 for c in text if c.isalpha())
        if alpha_count == 0:
            return text
        prepared_keyword = self._prepare_keyword(keyword, alpha_count)
        result = []
        key_index = 0
        for ch in text:
            if ch.isalpha():
                is_upper = ch.isupper()
                base = ord("A") if is_upper else ord("a")
                c_val = ord(ch.upper()) - ord("A")
                k = ord(prepared_keyword[key_index]) - ord("A")
                p = (c_val - k) % 26
                dec = chr(p + base)
                result.append(dec)
                key_index += 1
            else:
                result.append(ch)
        return "".join(result)

    def get_info(self):
        info = super().get_info()
        info.update(
            {
                "description": "Anahtar kelime tabanlı çoklu kaydırma şifrelemesi.",
                "required_params": ["keyword"],
                "param_descriptions": {
                    "keyword": "Anahtar kelime (sadece harflerden oluşmalı)"
                },
            }
        )
        return info
