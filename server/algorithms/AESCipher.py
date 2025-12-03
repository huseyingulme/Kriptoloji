"""
AES (Advanced Encryption Standard) Cipher implementasyonu
Modern simetrik blok şifreleme algoritması
"""
from server.algorithms.BaseCipher import BaseCipher
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import hashlib


class AESCipher(BaseCipher):
    
    # Desteklenen modlar
    SUPPORTED_MODES = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'GCM']
    # Desteklenen anahtar boyutları (bit cinsinden)
    SUPPORTED_KEY_SIZES = [128, 192, 256]
    # Default değerler
    DEFAULT_KEY_SIZE = 256
    DEFAULT_MODE = 'CBC'
    
    def __init__(self):
        super().__init__()
        self.name = "AES Cipher"
        self.description = "Advanced Encryption Standard - Modern simetrik blok şifreleme algoritması"
        self.key_type = "string"
        self.min_key_length = 8  # Minimum 8 karakter anahtar
        self.max_key_length = 200
        self.key_description = "Anahtar formatı: 'key' veya 'key_size:mode:key' (örn: '256:CBC:my_secret_key'). Modlar: ECB, CBC, CFB, OFB, CTR, GCM. Key size: 128, 192, 256"
        self.supports_binary = True
    
    def _parse_key_string(self, key_string: str) -> tuple:
        """
        Anahtar string'ini parse eder
        
        Formatlar:
        - "my_key" -> (256, 'CBC', 'my_key')
        - "128:CBC:my_key" -> (128, 'CBC', 'my_key')
        - "256:GCM:my_key" -> (256, 'GCM', 'my_key')
        
        Returns:
            (key_size, mode, key_string) tuple
        """
        parts = key_string.split(':', 2)
        
        if len(parts) == 1:
            # Sadece anahtar verilmiş, default değerleri kullan
            return (self.DEFAULT_KEY_SIZE, self.DEFAULT_MODE, parts[0])
        elif len(parts) == 3:
            # key_size:mode:key formatı
            try:
                key_size = int(parts[0])
                mode = parts[1].upper()
                key = parts[2]
                
                if key_size not in self.SUPPORTED_KEY_SIZES:
                    raise ValueError(f"Desteklenmeyen anahtar boyutu: {key_size}. Desteklenen: {self.SUPPORTED_KEY_SIZES}")
                
                if mode not in self.SUPPORTED_MODES:
                    raise ValueError(f"Desteklenmeyen mod: {mode}. Desteklenen: {self.SUPPORTED_MODES}")
                
                return (key_size, mode, key)
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Geçersiz anahtar formatı. Doğru format: 'key' veya 'key_size:mode:key'")
                raise
        else:
            raise ValueError(f"Geçersiz anahtar formatı. Doğru format: 'key' veya 'key_size:mode:key'")
    
    def _derive_key(self, key_string: str, key_size: int) -> bytes:
        """
        Anahtar string'inden belirtilen boyutta AES anahtarı türetir
        
        Args:
            key_string: Kullanıcı anahtarı
            key_size: İstenen anahtar boyutu (bit)
        
        Returns:
            bytes: Türetilmiş AES anahtarı
        """
        # PBKDF2 kullanarak sabit bir salt ile key türet
        # Not: Gerçek uygulamada salt'ı rastgele üretip saklamak gerekir
        salt = hashlib.sha256(key_string.encode()).digest()[:16]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size // 8,  # Byte'a çevir
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(key_string.encode())
        return key
    
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
        elif mode_name == 'CTR':
            if iv is None:
                raise ValueError("CTR modu için IV (nonce) gerekli")
            return modes.CTR(iv)
        elif mode_name == 'GCM':
            if iv is None:
                raise ValueError("GCM modu için IV (nonce) gerekli")
            return modes.GCM(iv)
        else:
            raise ValueError(f"Desteklenmeyen mod: {mode_name}")
    
    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        AES şifreleme
        
        Args:
            data: Şifrelenecek veri
            key: Anahtar string'i (format: 'key' veya 'key_size:mode:key')
        
        Returns:
            Şifrelenmiş veri (IV + şifreli veri formatında)
        """
        try:
            # Anahtarı parse et
            key_size, mode_name, key_string = self._parse_key_string(key)
            
            # AES anahtarını türet
            aes_key = self._derive_key(key_string, key_size)
            
            # IV/Nonce oluştur (ECB hariç tüm modlar için gerekli)
            if mode_name == 'ECB':
                iv = None
                mode = self._get_mode_object(mode_name)
            else:
                # GCM için 12 byte, diğerleri için 16 byte IV
                iv_length = 12 if mode_name == 'GCM' else 16
                iv = os.urandom(iv_length)
                mode = self._get_mode_object(mode_name, iv)
            
            # Cipher oluştur
            if key_size == 128:
                algorithm = algorithms.AES128(aes_key)
            elif key_size == 192:
                algorithm = algorithms.AES192(aes_key)
            else:  # 256
                algorithm = algorithms.AES256(aes_key)
            
            cipher = Cipher(algorithm, mode, backend=default_backend())
            encryptor = cipher.encryptor()
            
            # ECB ve CTR dışında padding gerekli
            if mode_name in ['ECB', 'CBC', 'CFB', 'OFB']:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(data)
                padded_data += padder.finalize()
            else:
                padded_data = data
            
            # Şifreleme
            if mode_name == 'GCM':
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                # GCM için tag eklenir
                result = iv + ciphertext + encryptor.tag
            else:
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                # IV'yi başa ekle
                result = iv + ciphertext if iv else ciphertext
            
            return result
            
        except ValueError as e:
            raise ValueError(f"Anahtar hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")
    
    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        AES çözme
        
        Args:
            data: Çözülecek veri (IV + şifreli veri formatında)
            key: Anahtar string'i (format: 'key' veya 'key_size:mode:key')
        
        Returns:
            Çözülmüş veri
        """
        try:
            # Anahtarı parse et
            key_size, mode_name, key_string = self._parse_key_string(key)
            
            # AES anahtarını türet
            aes_key = self._derive_key(key_string, key_size)
            
            # IV'yi ve şifreli veriyi ayır
            if mode_name == 'ECB':
                iv = None
                encrypted_data = data
            elif mode_name == 'GCM':
                # GCM: IV (12 byte) + ciphertext + tag (16 byte)
                iv_length = 12
                tag_length = 16
                if len(data) < iv_length + tag_length:
                    raise ValueError("Geçersiz şifreli veri formatı")
                iv = data[:iv_length]
                tag = data[-tag_length:]
                encrypted_data = data[iv_length:-tag_length]
            else:
                # Diğer modlar: IV (16 byte) + ciphertext
                iv_length = 16
                if len(data) < iv_length:
                    raise ValueError("Geçersiz şifreli veri formatı")
                iv = data[:iv_length]
                encrypted_data = data[iv_length:]
            
            # Mode oluştur
            if mode_name == 'GCM':
                mode = modes.GCM(iv, tag)
            else:
                mode = self._get_mode_object(mode_name, iv) if iv else self._get_mode_object(mode_name)
            
            # Cipher oluştur
            if key_size == 128:
                algorithm = algorithms.AES128(aes_key)
            elif key_size == 192:
                algorithm = algorithms.AES192(aes_key)
            else:  # 256
                algorithm = algorithms.AES256(aes_key)
            
            cipher = Cipher(algorithm, mode, backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Çözme
            if mode_name == 'GCM':
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            else:
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Padding'i kaldır (ECB ve CTR dışında)
            if mode_name in ['ECB', 'CBC', 'CFB', 'OFB']:
                unpadder = padding.PKCS7(128).unpadder()
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
        AES anahtar geçerliliğini kontrol eder
        
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

