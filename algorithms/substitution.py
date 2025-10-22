from .base import TextEncryptionAlgorithm
from typing import Union, Dict
import random
import string


class SubstitutionCipher(TextEncryptionAlgorithm):
    def __init__(self):
        super().__init__("Substitution")
        self.required_params = ["substitution_key"]

    def _generate_random_key(self) -> str:
        alphabet = list(string.ascii_uppercase)
        random.shuffle(alphabet)
        return "".join(alphabet)

    def _validate_substitution_key(self, key: str) -> bool:
        if not isinstance(key, str):
            return False
        k = key.upper()
        if len(k) != 26:
            return False
        if len(set(k)) != 26:
            return False
        return all(c.isalpha() for c in k)

    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: substitution_key")
        substitution_key = str(kwargs["substitution_key"]).upper()
        if not self._validate_substitution_key(substitution_key):
            raise ValueError("Geçersiz yerine geçme anahtarı. 26 unique harf olmalı.")
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        mapping_upper = {chr(i + ord("A")): substitution_key[i] for i in range(26)}
        mapping_lower = {k.lower(): v.lower() for k, v in mapping_upper.items()}
        result_chars = []
        for ch in text:
            if ch.isupper() and ch.isalpha():
                result_chars.append(mapping_upper.get(ch, ch))
            elif ch.islower() and ch.isalpha():
                result_chars.append(mapping_lower.get(ch, ch))
            else:
                result_chars.append(ch)
        return "".join(result_chars)

    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: substitution_key")
        substitution_key = str(kwargs["substitution_key"]).upper()
        if not self._validate_substitution_key(substitution_key):
            raise ValueError("Geçersiz yerine geçme anahtarı. 26 unique harf olmalı.")
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        reverse_upper = {substitution_key[i]: chr(i + ord("A")) for i in range(26)}
        reverse_lower = {k.lower(): v.lower() for k, v in reverse_upper.items()}
        result_chars = []
        for ch in text:
            if ch.isupper() and ch.isalpha():
                result_chars.append(reverse_upper.get(ch, ch))
            elif ch.islower() and ch.isalpha():
                result_chars.append(reverse_lower.get(ch, ch))
            else:
                result_chars.append(ch)
        return "".join(result_chars)

    def generate_key(self) -> str:
        return self._generate_random_key()

    def get_info(self) -> Dict:
        info = super().get_info()
        info.update(
            {
                "description": "Harf yerine geçme tabanlı şifreleme. Her harf başka bir harfle değiştirilir.",
                "required_params": ["substitution_key"],
                "param_descriptions": {
                    "substitution_key": "26 harfli yerine geçme anahtarı (A-Z harflerinin karışık sırası)"
                },
            }
        )
        return info
