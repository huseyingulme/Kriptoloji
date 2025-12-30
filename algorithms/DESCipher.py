from algorithms.BaseCipher import BaseCipher
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
import os
import hashlib
from shared.utils import CryptoUtils

class DESCipher(BaseCipher):
    """
    Data Encryption Standard (DES) Şifrelemesi (Kütüphaneli - TripleDES Tabanlı).
    
    Bu sınıf, 8-baytlık DES anahtarını 3 kez tekrarlayarak (K1=K2=K3) TripleDES'in 
    (3DES-EDE1) tek anahtarlı yapısını kullanarak DES benzeri işlevsellik sağlar.
    """
    
    # Desteklenen DES çalışma modları
    SUPPORTED_MODES = ['ECB', 'CBC', 'CFB', 'OFB']
    
    # DES'in blok boyutu (64 bit) ve anahtar türetme hedefi (8 byte)
    DES_BLOCK_SIZE = 8
    DES_KEY_DERIVE_SIZE = 8
    DEFAULT_MODE = 'CBC'

    def __init__(self):
        super().__init__()
        self.name = "DES Cipher (Kütüphaneli - 3DES Tabanlı)"
        self.description = "Data Encryption Standard (Kütüphane tabanlı 3DES ile simülasyon)"
        self.key_type = "string"
        self.min_key_length = 1 
        self.max_key_length = 200
        self.key_description = "Anahtar formatı: 'key' veya 'mode:key' (örn: 'CBC:my_secret_key'). Modlar: ECB, CBC, CFB, OFB."
        self.supports_binary = True


    def _parse_key_string(self, key_string: str) -> Tuple[str, str]:
        """Anahtar dizesini mod ve key string olarak ayrıştırır."""
        
        parts = key_string.split(':')

        if len(parts) == 1:
            mode = self.DEFAULT_MODE
            key_str = parts[0]
        elif len(parts) == 2:
            mode = parts[0].upper()
            key_str = parts[1]
        elif len(parts) == 3:
            # "DES:CBC:key" formatını destekle
            if parts[0].upper() == "DES":
                mode = parts[1].upper()
                key_str = parts[2]
            else:
                raise ValueError("Geçersiz DES anahtar formatı. Doğru format: 'key' veya 'mode:key' veya 'DES:mode:key'")
        else:
            raise ValueError("Geçersiz anahtar formatı. Doğru format: 'key' veya 'mode:key'")

        if mode not in self.SUPPORTED_MODES:
            raise ValueError(f"Desteklenmeyen mod: {mode}. Desteklenen: {self.SUPPORTED_MODES}")

        return (mode, key_str)

    def _derive_key(self, key_string: str) -> bytes:
        """Kullanıcı anahtarından 8 byte (64-bit) DES anahtarı türetir."""
        if not key_string:
            raise ValueError("Anahtar boş olamaz.")
        
        # 1. Akıllı Anahtar Tespiti (Hex, B64, Raw)
        derived_key = CryptoUtils.derive_key_robust(key_string, expected_sizes=[8])
        
        # Eğer zaten 8 bytes ise direkt döndür
        if len(derived_key) == self.DES_KEY_DERIVE_SIZE:
            return derived_key

        # 2. Aksi takdirde SHA256 ile anahtar türetilir ve ilk 8 byte alınır.
        key_hash = hashlib.sha256(derived_key).digest()
        des_key = key_hash[:self.DES_KEY_DERIVE_SIZE] 
        return des_key

    def _get_mode_object(self, mode_name: str, iv: bytes = None):
        """Mod objesini döndürür."""
        
        if mode_name == 'ECB':
            return modes.ECB()
        
        # IV/Nonce gerektiren modlar için kontrol
        if iv is None:
            raise ValueError(f"{mode_name} modu için IV ({self.DES_BLOCK_SIZE} byte) gerekli")

        if mode_name == 'CBC':
            return modes.CBC(iv)
        elif mode_name == 'CFB':
            return modes.CFB(iv)
        elif mode_name == 'OFB':
            return modes.OFB(iv)
        else:
            raise ValueError(f"Desteklenmeyen mod: {mode_name}")

    # --- Şifreleme Metotları ---

    def encrypt(self, data: bytes, key: str) -> bytes:
        """DES (TripleDES tabanlı) ile veriyi şifreler."""
        try:
            mode_name, key_string = self._parse_key_string(key)
            des_key = self._derive_key(key_string)
            
            # TripleDES Anahtarı: 8 byte anahtar 3 kez tekrarlanır (24 byte).
            triple_des_key = des_key * 3
            
            # IV Yönetimi
            iv = None
            if mode_name != 'ECB':
                iv = os.urandom(self.DES_BLOCK_SIZE) # Rastgele 8 byte IV
            
            mode = self._get_mode_object(mode_name, iv)
            algorithm = algorithms.TripleDES(triple_des_key)
            

            cipher = Cipher(algorithm, mode, backend=default_backend())
            encryptor = cipher.encryptor()

            # Padding (Blok şifreleme modları ECB ve CBC için zorunlu)
            if mode_name in ['ECB', 'CBC']:
                padder = padding.PKCS7(algorithms.TripleDES.block_size).padder() # 64 bit = 8 byte
                padded_data = padder.update(data) + padder.finalize()
            else:
                # Akış (Stream) modları için padding gerekli değildir.
                padded_data = data

            # Şifreleme
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Sonuç paketleme: IV varsa IV + Ciphertext
            result = iv + ciphertext if iv else ciphertext
            return result

        except ValueError as e:
            raise ValueError(f"Anahtar/Parametre hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """DES (TripleDES tabanlı) ile şifrelenmiş veriyi çözer."""
        try:
            mode_name, key_string = self._parse_key_string(key)
            des_key = self._derive_key(key_string)
            triple_des_key = des_key * 3 # Anahtar türetme
            
            # 1. Gelen Veriden IV/Nonce Ayırma
            iv = None
            encrypted_data = data
            
            if mode_name != 'ECB':
                iv_length = self.DES_BLOCK_SIZE
                if len(data) < iv_length:
                    raise ValueError(f"{mode_name}: Eksik IV ({iv_length} byte) bilgisi.")
                iv = data[:iv_length]
                encrypted_data = data[iv_length:]
            
            mode = self._get_mode_object(mode_name, iv)
            algorithm = algorithms.TripleDES(triple_des_key)
            
            cipher = Cipher(algorithm, mode, backend=default_backend())
            decryptor = cipher.decryptor()

            # Deşifreleme
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Unpadding (ECB ve CBC için)
            if mode_name in ['ECB', 'CBC']:
                unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
                result = unpadder.update(decrypted_data) + unpadder.finalize()
            else:
                result = decrypted_data

            return result

        except ValueError as e:
            raise ValueError(f"Anahtar/Parametre hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        """Anahtar dizesinin geçerli format, mod ve boyuta sahip olup olmadığını kontrol eder."""
        try:
            # Parsing ve türetme işlemini kontrol et
            mode, key_str = self._parse_key_string(key)
            self._derive_key(key_str)
            return True
        except ValueError:
            return False
        except Exception:
             return False