from .base import TextEncryptionAlgorithm
from typing import Union


class CaesarCipher(TextEncryptionAlgorithm):
    def __init__(self):
        super().__init__("Caesar")
        self.required_params = ["shift"]

    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: shift")
        shift = int(kwargs["shift"]) % 26
        text = data if isinstance(data, str) else data.decode("utf-8")
        result = ""
        for c in text:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                result += chr((ord(c) - base + shift) % 26 + base)
            else:
                result += c
        return result

    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: shift")
        shift = -int(kwargs["shift"]) % 26
        return self.encrypt(data, shift=shift)

    def get_info(self):
        info = super().get_info()
        info.update(
            {
                "description": "Her harfi belirli bir miktar kaydırarak şifreleyen klasik algoritma.",
                "required_params": ["shift"],
                "param_descriptions": {
                    "shift": "Kaydırma miktarı (0-25 arası tam sayı)"
                },
            }
        )
        return info
