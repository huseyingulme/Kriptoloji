from algorithms.BaseCipher import BaseCipher
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import hashlib
import base64 # base64 kullanılmamış ama import edilmiş, bu sürümde kaldırılmıştır.

class AESCipher(BaseCipher):

    # AES 128/192/256 için desteklenen anahtar boyutları
    SUPPORTED_KEY_SIZES = [128, 192, 256]
    # Desteklenen Modlar listesi
    SUPPORTED_MODES = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'GCM']
    
    # Varsayılan ayarlar
    DEFAULT_KEY_SIZE = 256
    DEFAULT_MODE = 'CBC'
    
    # GCM modu için zorunlu tag uzunluğu (Authentication Tag)
    GCM_TAG_LENGTH = 16 

    def __init__(self):
        super().__init__()
        self.name = "AES Cipher (Library)"
        self.description = "Advanced Encryption Standard - Kütüphane tabanlı simetrik blok şifreleme"
        self.key_type = "string"
        self.min_key_length = 8
        self.max_key_length = 200
        self.key_description = "Anahtar formatı: 'key' veya 'key_size:mode:key' (örn: '256:CBC:my_secret_key'). Modlar: ECB, CBC, CFB, OFB, CTR, GCM. Key size: 128, 192, 256"
        self.supports_binary = True

    # --- Yardımcı Metotlar ---

    def _get_aes_algorithm(self, aes_key: bytes, key_size: int):
        """Anahtar boyutuna göre AES algoritma objesini döndürür."""
        if key_size == 128:
            return algorithms.AES128(aes_key)
        elif key_size == 192:
            return algorithms.AES192(aes_key)
        elif key_size == 256:
            return algorithms.AES256(aes_key)
        else:
            raise ValueError(f"Desteklenmeyen anahtar boyutu: {key_size}")

    def _parse_key_string(self, key_string: str) -> tuple[int, str, str]:
        """Anahtar dizesini boyut, mod ve key string olarak ayrıştırır."""
        
        parts = key_string.split(':', 2)

        if len(parts) == 1:
            key_size = self.DEFAULT_KEY_SIZE
            mode = self.DEFAULT_MODE
            key_str = parts[0]
        elif len(parts) == 3:
            try:
                key_size = int(parts[0])
                mode = parts[1].upper()
                key_str = parts[2]
            except ValueError:
                raise ValueError("Geçersiz anahtar formatı. Anahtar boyutu tamsayı olmalıdır.")
        else:
            raise ValueError("Geçersiz anahtar formatı. Doğru format: 'key' veya 'key_size:mode:key'")
        
        if key_size not in self.SUPPORTED_KEY_SIZES:
            raise ValueError(f"Desteklenmeyen anahtar boyutu: {key_size}. Desteklenen: {self.SUPPORTED_KEY_SIZES}")

        if mode not in self.SUPPORTED_MODES:
            raise ValueError(f"Desteklenmeyen mod: {mode}. Desteklenen: {self.SUPPORTED_MODES}")

        return (key_size, mode, key_str)

    def _derive_key(self, key_string: str, key_size: int) -> bytes:
        """PBKDF2HMAC kullanarak kullanıcı anahtarından kriptografik anahtar türetir."""
        # Salt olarak anahtar stringinin SHA256 özetinin ilk 16 byte'ı kullanılır.
        salt = hashlib.sha256(key_string.encode()).digest()[:16]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size // 8,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        key = kdf.derive(key_string.encode())
        return key

    def _get_mode_object(self, mode_name: str, iv: bytes = None, tag: bytes = None):
        """Mod objesini döndürür, ECB için IV/Nonce istemez."""

        if mode_name == 'ECB':
            if iv is not None or tag is not None:
                 raise ValueError("ECB modu IV veya Tag kabul etmez.")
            return modes.ECB()
        
        # IV/Nonce gerektiren modlar için kontrol
        if iv is None:
            raise ValueError(f"{mode_name} modu için IV/Nonce gerekli")

        if mode_name == 'CBC':
            return modes.CBC(iv)
        elif mode_name == 'CFB':
            return modes.CFB(iv)
        elif mode_name == 'OFB':
            return modes.OFB(iv)
        elif mode_name == 'CTR':
            return modes.CTR(iv)
        elif mode_name == 'GCM':
            # GCM için deşifrelemede tag parametresi kullanılır
            return modes.GCM(iv, tag) 
        else:
            raise ValueError(f"Desteklenmeyen mod: {mode_name}")

    # --- Şifreleme Metotları ---
    
    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        AES ile veriyi şifreler (Kütüphaneli).
        Returns: bytes: Şifrelenmiş veri (IV/Nonce + ciphertext + GCM Tag)
        """
        try:
            key_size, mode_name, key_string = self._parse_key_string(key)
            aes_key = self._derive_key(key_string, key_size)
            algorithm = self._get_aes_algorithm(aes_key, key_size)
            
            # 1. IV/Nonce Üretimi (ECB hariç)
            iv = None
            if mode_name != 'ECB':
                # AES blok boyutu 16 byte'dır. GCM Nonce boyutu genellikle 12 byte'dır.
                iv_length = 12 if mode_name == 'GCM' else 16
                iv = os.urandom(iv_length)
            
            # 2. Mod objesi oluşturma
            mode = self._get_mode_object(mode_name, iv)
            cipher = Cipher(algorithm, mode, backend=default_backend())
            encryptor = cipher.encryptor()

            # 3. Padding (ECB, CBC, CFB, OFB için)
            if mode_name in ['ECB', 'CBC']: # CFB, OFB genellikle padding istemez, ECB ve CBC blok şifreleme modlarında zorunludur.
                padder = padding.PKCS7(algorithms.AES.block_size).padder() # 128 bit = 16 byte
                padded_data = padder.update(data) + padder.finalize()
            else:
                padded_data = data

            # 4. Şifreleme
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # 5. Sonuç paketleme (IV + Ciphertext + Tag)
            result = ciphertext
            if mode_name == 'GCM':
                result = iv + ciphertext + encryptor.tag
            elif iv:
                result = iv + ciphertext
            
            return result

        except ValueError as e:
            raise ValueError(f"Anahtar/Parametre hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        AES ile şifrelenmiş veriyi çözer (Kütüphaneli).
        Returns: bytes: Çözülmüş veri (Plaintext)
        """
        try:
            key_size, mode_name, key_string = self._parse_key_string(key)
            aes_key = self._derive_key(key_string, key_size)
            algorithm = self._get_aes_algorithm(aes_key, key_size)
            
            iv = None
            tag = None
            encrypted_data = data
            
            # 1. Gelen veriden IV/Nonce ve Tag'ı ayırma
            if mode_name == 'ECB':
                pass # IV/Nonce/Tag yok
            elif mode_name == 'GCM':
                iv_length = 12
                if len(data) < iv_length + self.GCM_TAG_LENGTH:
                     raise ValueError("GCM: Eksik IV/Nonce veya Tag.")
                iv = data[:iv_length]
                tag = data[-self.GCM_TAG_LENGTH:]
                encrypted_data = data[iv_length:-self.GCM_TAG_LENGTH]
            else:
                iv_length = 16
                if len(data) < iv_length:
                    raise ValueError(f"{mode_name}: Eksik IV/Nonce bilgisi.")
                iv = data[:iv_length]
                encrypted_data = data[iv_length:]

            # 2. Mod objesi oluşturma
            mode = self._get_mode_object(mode_name, iv, tag)
            cipher = Cipher(algorithm, mode, backend=default_backend())
            decryptor = cipher.decryptor()

            # 3. Deşifreleme (GCM, tag'ı otomatik kontrol eder)
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # 4. Unpadding (ECB, CBC için)
            if mode_name in ['ECB', 'CBC']:
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                result = unpadder.update(decrypted_data) + unpadder.finalize()
            else:
                result = decrypted_data

            return result

        except modes.InvalidTag:
            # GCM veya diğer Authenticated Encryption modlarında kimlik doğrulama hatası
            raise Exception("Deşifreleme hatası: Kimlik doğrulama (Authentication Tag) başarısız.")
        except ValueError as e:
            raise ValueError(f"Anahtar/Parametre hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        """Anahtar dizesinin geçerli format, mod ve boyuta sahip olup olmadığını kontrol eder."""
        try:
            # Anahtar türetme işlemi yapılmadığı için sadece parsing kontrolü yeterlidir.
            self._parse_key_string(key)
            return True
        except ValueError:
            return False
        except Exception:
             # Diğer beklenmeyen hatalar için
             return False

# Özet: AES şifreleme adımları (Kütüphane)
# AES (Advanced Encryption Standard), bir Feistel ağı kullanmaz; bunun yerine bir Substitution-Permutation Network (SPN) kullanır.
# 1. Tur Anahtarı Ekleme (AddRoundKey)
# 2. 9/11/13 Normal Tur: Bayt Değiştirme (SubBytes) → Satır Kaydırma (ShiftRows) → Sütun Karıştırma (MixColumns) → Tur Anahtarı Ekleme (AddRoundKey)
# 3. Son Tur: Bayt Değiştirme (SubBytes) → Satır Kaydırma (ShiftRows) → Tur Anahtarı Ekleme (AddRoundKey)

# Not: Verilen kodda şifreleme ve çözme işlemleri sırasında kütüphanenin çağrılmasıyla bu adımlar
# otomatik olarak gerçekleştirilir. Öğrencinin "Manuel Mod" için bu adımları kendisi kodlaması gerekecektir.