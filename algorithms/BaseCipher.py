"""
BaseCipher - Tüm Şifreleme Algoritmalarının Temel Sınıfı

Bu sınıf, tüm şifreleme algoritmalarının ortak arayüzünü tanımlar.
Yeni bir algoritma eklemek için bu sınıftan türetilmeli ve 
encrypt() ile decrypt() metodları mutlaka implement edilmelidir.
"""

from abc import ABC, abstractmethod


class BaseCipher(ABC):
    def __init__(self):
        """Temel algoritma özelliklerini başlatır."""
        self.name: str = "BaseCipher"
        self.description: str = "Temel şifreleme sınıfı"
        self.key_type: str = "string"
        self.supports_binary: bool = True
        self.min_key_length: int = 1
        self.max_key_length: int = 256


    @abstractmethod
    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Veriyi şifreler.

        Args:
            data (bytes): Şifrelenecek ham veri.
            key (str): Şifreleme anahtarı.

        Returns:
            bytes: Şifrelenmiş veri.
        """
        raise NotImplementedError("encrypt() metodu implement edilmelidir.")

    @abstractmethod
    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        Şifrelenmiş veriyi çözer.

        Args:
            data (bytes): Şifreli veri.
            key (str): Şifre çözme anahtarı.

        Returns:
            bytes: Çözülmüş veri.
        """
        raise NotImplementedError("decrypt() metodu implement edilmelidir.")


    def validate_key(self, key: str) -> bool:
        """
        Anahtarın geçerliliğini kontrol eder.

        Varsayılan kurallar:
        - Anahtar boş olmamalı
        - Uzunluğu min ve max arasında olmalı

        Override edilerek algoritmaya özel kontrol eklenebilir.
        """
        return (
            isinstance(key, str)
            and len(key) >= self.min_key_length
            and len(key) <= self.max_key_length
        )

    # ---------------------------------------------------------------------

    def _prepare_data(self, data: bytes) -> bytes:
        """
        Veriyi şifreleme için hazırlar.

        Algoritmalar isterse override edebilir.
        """
        return data

    def _finalize_data(self, data: bytes) -> bytes:
        """
        Şifreleme/şifre çözme sonrası veriyi finalize eder.

        Algoritmalar override edebilir.
        """
        return data
