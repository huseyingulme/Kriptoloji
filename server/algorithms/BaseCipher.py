"""
BaseCipher - Tüm Şifreleme Algoritmalarının Temel Sınıfı

Bu sınıf, tüm şifreleme algoritmalarının ortak özelliklerini ve
temel yapısını tanımlar. Her algoritma bu sınıftan türetilmelidir.
"""

from abc import ABC, abstractmethod
from typing import Union


class BaseCipher(ABC):
    """
    Tüm şifreleme algoritmalarının temel sınıfı.
    
    Bu sınıf, her algoritmanın sahip olması gereken temel özellikleri
    ve metodları tanımlar. Yeni bir algoritma eklemek için bu sınıftan
    türetilmeli ve encrypt() ile decrypt() metodları implement edilmelidir.
    """

    def __init__(self):
        """Temel özellikleri başlatır."""
        self.name = "BaseCipher"
        self.description = "Temel şifreleme sınıfı"
        self.key_type = "string"  # "string", "integer", "matrix" vb.
        self.supports_binary = True  # Binary veri (resim, ses, video) destekleniyor mu?
        self.min_key_length = 1  # Minimum anahtar uzunluğu
        self.max_key_length = 256  # Maksimum anahtar uzunluğu

    @abstractmethod
    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Veriyi şifreler (soyut metod - her algoritma kendi implementasyonunu yapmalı).
        
        Args:
            data: Şifrelenecek veri (bytes)
            key: Şifreleme anahtarı (string)
            
        Returns:
            bytes: Şifrelenmiş veri
        """
        pass

    @abstractmethod
    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        Şifrelenmiş veriyi çözer (soyut metod - her algoritma kendi implementasyonunu yapmalı).
        
        Args:
            data: Çözülecek veri (bytes)
            key: Şifreleme anahtarı (string)
            
        Returns:
            bytes: Çözülmüş veri
        """
        pass

    def validate_key(self, key: str) -> bool:
        """
        Anahtarın geçerli olup olmadığını kontrol eder.
        
        Varsayılan kontrol: Anahtar boş olmamalı ve uzunluk sınırları içinde olmalı.
        Algoritmalar bu metodu override ederek kendi kontrollerini yapabilir.
        
        Args:
            key: Kontrol edilecek anahtar
            
        Returns:
            bool: Anahtar geçerliyse True
        """
        if not key:
            return False

        if len(key) < self.min_key_length:
            return False

        if len(key) > self.max_key_length:
            return False

        return True

    def _prepare_data(self, data: bytes) -> bytes:
        """
        Veriyi işleme hazırlar (opsiyonel - override edilebilir).
        
        Bazı algoritmalar veriyi işlemeden önce özel hazırlık yapabilir.
        """
        return data

    def _finalize_data(self, data: bytes) -> bytes:
        """
        İşlenmiş veriyi son haline getirir (opsiyonel - override edilebilir).
        
        Bazı algoritmalar veriyi işledikten sonra özel işlemler yapabilir.
        """
        return data
