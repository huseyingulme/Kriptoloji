"""
DES (Data Encryption Standard) Cipher implementasyonu
Klasik simetrik blok şifreleme algoritması
"""
from server.algorithms.BaseCipher import BaseCipher
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import hashlib


class DESCipher(BaseCipher):
    
    # Desteklenen modlar
    SUPPORTED_MODES = ['ECB', 'CBC', 'CFB', 'OFB']
    # DES anahtar boyutu (bit cinsinden) - 64 bit (8 byte), ancak sadece 56 bit kullanılır
    DES_KEY_SIZE = 64
    # Default değerler
    DEFAULT_MODE = 'CBC'
    
    def __init__(self):
        super().__init__()
        self.name = "DES Cipher"
        self.description = "Data Encryption Standard - Klasik simetrik blok şifreleme algoritması (64-bit blok, 56-bit efektif anahtar)"
        self.key_type = "string"
        self.min_key_length = 8  # Minimum 8 karakter anahtar (64 bit)
        self.max_key_length = 200
        self.key_description = "Anahtar formatı: 'key' veya 'mode:key' (örn: 'CBC:my_secret_key'). Modlar: ECB, CBC, CFB, OFB"
        self.supports_binary = True
    
    def _parse_key_string(self, key_string: str) -> tuple:
        """
        Anahtar string'ini parse eder
        
        Formatlar:
        - "my_key" -> ('CBC', 'my_key')
        - "CBC:my_key" -> ('CBC', 'my_key')
        - "ECB:my_key" -> ('ECB', 'my_key')
        
        Returns:
            (mode, key_string) tuple
        """
        parts = key_string.split(':', 1)
        
        if len(parts) == 1:
            # Sadece anahtar verilmiş, default modu kullan
            return (self.DEFAULT_MODE, parts[0])
        elif len(parts) == 2:
            # mode:key formatı
            mode = parts[0].upper()
            key = parts[1]
            
            if mode not in self.SUPPORTED_MODES:
                raise ValueError(f"Desteklenmeyen mod: {mode}. Desteklenen: {self.SUPPORTED_MODES}")
            
            return (mode, key)
        else:
            raise ValueError(f"Geçersiz anahtar formatı. Doğru format: 'key' veya 'mode:key'")
    
    def _derive_key(self, key_string: str) -> bytes:
        """
        Anahtar string'inden DES anahtarı türetir (8 byte = 64 bit)
        
        Args:
            key_string: Kullanıcı anahtarı
        
        Returns:
            bytes: Türetilmiş DES anahtarı (8 byte)
        """
        # SHA256 hash kullanarak 8 byte anahtar türet
        key_hash = hashlib.sha256(key_string.encode()).digest()
        # İlk 8 byte'ı al (DES 64-bit anahtar kullanır)
        des_key = key_hash[:8]
        return des_key
    
    def _get_mode_object(self, mode_name: str, iv: bytes = None):
        """
        Mod adından mode objesi oluşturur
        
        Args:
            mode_name: Mod adı (ECB, CBC, vb.)
            iv: Initialization Vector (gerekli modlar için)
        
        Returns:
            Mode objesi
        """
        if mode_name == 'ECB':
            return modes.ECB()
        elif mode_name == 'CBC':
            if iv is None:
                raise ValueError("CBC modu için IV gerekli")
            return modes.CBC(iv)
        elif mode_name == 'CFB':
            if iv is None:
                raise ValueError("CFB modu için IV gerekli")
            return modes.CFB(iv)
        elif mode_name == 'OFB':
            if iv is None:
                raise ValueError("OFB modu için IV gerekli")
            return modes.OFB(iv)
        else:
            raise ValueError(f"Desteklenmeyen mod: {mode_name}")
    
    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        DES şifreleme
        
        Args:
            data: Şifrelenecek veri
            key: Anahtar string'i (format: 'key' veya 'mode:key')
        
        Returns:
            Şifrelenmiş veri (IV + şifreli veri formatında)
        """
        try:
            # Anahtarı parse et
            mode_name, key_string = self._parse_key_string(key)
            
            # DES anahtarını türet
            des_key = self._derive_key(key_string)
            
            # IV/Nonce oluştur (ECB hariç tüm modlar için gerekli)
            if mode_name == 'ECB':
                iv = None
                mode = self._get_mode_object(mode_name)
            else:
                # DES için 8 byte IV (blok boyutu)
                iv = os.urandom(8)
                mode = self._get_mode_object(mode_name, iv)
            
            # Cipher oluştur
            # Not: Modern cryptography kütüphanesi DES'i desteklemez, TripleDES kullanıyoruz
            # TripleDES 1-key mode (EDE): aynı anahtarı 3 kez kullanır (DES benzeri)
            # 24 byte anahtar gerektirir, bu yüzden anahtarı 3 kez tekrarlıyoruz
            triple_des_key = des_key * 3  # 8 byte * 3 = 24 byte
            algorithm = algorithms.TripleDES(triple_des_key)
            
            cipher = Cipher(algorithm, mode, backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Padding gerekli (ECB ve CBC için)
            if mode_name in ['ECB', 'CBC']:
                padder = padding.PKCS7(64).padder()  # DES 64-bit blok kullanır
                padded_data = padder.update(data)
                padded_data += padder.finalize()
            else:
                padded_data = data
            
            # Şifreleme
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # IV'yi başa ekle (ECB hariç)
            result = iv + ciphertext if iv else ciphertext
            
            return result
            
        except ValueError as e:
            raise ValueError(f"Anahtar hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")
    
    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        DES çözme
        
        Args:
            data: Çözülecek veri (IV + şifreli veri formatında)
            key: Anahtar string'i (format: 'key' veya 'mode:key')
        
        Returns:
            Çözülmüş veri
        """
        try:
            # Anahtarı parse et
            mode_name, key_string = self._parse_key_string(key)
            
            # DES anahtarını türet
            des_key = self._derive_key(key_string)
            
            # IV'yi ve şifreli veriyi ayır
            if mode_name == 'ECB':
                iv = None
                encrypted_data = data
            else:
                # DES için 8 byte IV
                iv_length = 8
                if len(data) < iv_length:
                    raise ValueError("Geçersiz şifreli veri formatı")
                iv = data[:iv_length]
                encrypted_data = data[iv_length:]
            
            # Mode oluştur
            mode = self._get_mode_object(mode_name, iv) if iv else self._get_mode_object(mode_name)
            
            # Cipher oluştur
            # TripleDES için 24 byte anahtar (anahtarı 3 kez tekrarla)
            triple_des_key = des_key * 3  # 8 byte * 3 = 24 byte
            algorithm = algorithms.TripleDES(triple_des_key)
            cipher = Cipher(algorithm, mode, backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Çözme
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Padding'i kaldır (ECB ve CBC için)
            if mode_name in ['ECB', 'CBC']:
                unpadder = padding.PKCS7(64).unpadder()
                result = unpadder.update(decrypted_data)
                result += unpadder.finalize()
            else:
                result = decrypted_data
            
            return result
            
        except ValueError as e:
            raise ValueError(f"Anahtar hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")
    
    def validate_key(self, key: str) -> bool:
        """
        DES anahtar geçerliliğini kontrol eder
        
        Args:
            key: Kontrol edilecek anahtar
        
        Returns:
            Anahtar geçerliliği
        """
        try:
            self._parse_key_string(key)
            return True
        except (ValueError, Exception):
            return False

