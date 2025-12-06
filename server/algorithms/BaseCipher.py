from abc import ABC, abstractmethod
from typing import Union

class BaseCipher(ABC):

    def __init__(self):
        self.name = "BaseCipher"
        self.description = "Temel şifreleme sınıfı"
        self.key_type = "string"
        self.supports_binary = True
        self.min_key_length = 1
        self.max_key_length = 256

    @abstractmethod
    def encrypt(self, data: bytes, key: str) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data: bytes, key: str) -> bytes:
        pass

    def validate_key(self, key: str) -> bool:
        if not key:
            return False

        if len(key) < self.min_key_length:
            return False

        if len(key) > self.max_key_length:
            return False

        return True

    def _prepare_data(self, data: bytes) -> bytes:
        return data

    def _finalize_data(self, data: bytes) -> bytes:
        return data
