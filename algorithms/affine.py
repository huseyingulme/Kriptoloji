from .base import TextEncryptionAlgorithm
from typing import Union

class AffineCipher(TextEncryptionAlgorithm):
    def __init__(self):
        super().__init__("Affine")
        self.required_params = ['a', 'b']

    def _gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a: int, m: int) -> int:
        if self._gcd(a, m) != 1:
            raise ValueError(f"{a} ve {m} aralarında asal değil, modüler ters bulunamaz")
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y
        return egcd(a, m)[1] % m

    def _validate_params(self, a: int, b: int) -> bool:
        return 1 <= a <= 25 and 0 <= b <= 25 and self._gcd(a, 26) == 1

    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: a, b")
        a, b = int(kwargs['a']), int(kwargs['b'])
        if not self._validate_params(a, b):
            raise ValueError("a 26 ile aralarında asal olmalı, b 0-25 arası olmalı")
        text = data.decode() if isinstance(data, bytes) else data
        result = ""
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                x = ord(c) - base
                result += chr((a * x + b) % 26 + base)
            else:
                result += c
        return result

    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: a, b")
        a, b = int(kwargs['a']), int(kwargs['b'])
        if not self._validate_params(a, b):
            raise ValueError("a 26 ile aralarında asal olmalı, b 0-25 arası olmalı")
        text = data.decode() if isinstance(data, bytes) else data
        a_inv = self._mod_inverse(a, 26)
        result = ""
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                y = ord(c) - base
                result += chr((a_inv * (y - b)) % 26 + base)
            else:
                result += c
        return result

    def get_info(self):
        info = super().get_info()
        info.update({
            'description': 'E(x) = (a*x + b) mod 26 formülüne dayalı klasik şifreleme algoritması.',
            'required_params': ['a', 'b'],
            'param_descriptions': {
                'a': 'Çarpan katsayısı (1-25, 26 ile aralarında asal olmalı)',
                'b': 'Toplama katsayısı (0-25)'
            }
        })
        return info
