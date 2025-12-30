from algorithms.BaseCipher import BaseCipher
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64

class RSACipher(BaseCipher):
    """
    🔐 [Algorithm Overview]
    Type: Asymmetric Cipher (RSA)
    Primary Use: KEY ENCRYPTION / DISTRIBUTION (Not for direct message text)

    🔒 KRİPTO FELSEFESİ:
    "Asimetrik algoritmalar (RSA) veri şifrelemez, sadece anahtar şifreler."
    - Yavaşlık ve blok yapısı nedeniyle büyük veriler için uygun değildir.
    - Metin şifrelemek verimsizdir.
    - Bu projede simetrik seans anahtarlarını (AES/DES) güvenli dağıtmak için kullanılır.
    - RSA = Anahtar Koruma Aracı.
    """

    DEFAULT_KEY_SIZE = 2048  # RSA anahtar boyutu (bit)
    SUPPORTED_KEY_SIZES = [1024, 2048, 3072, 4096]
    
    # OAEP Padding için kullanılan Hash boyutu (SHA256)
    OAEP_HASH_SIZE = 32 # bytes

    def __init__(self):
        super().__init__()
        self.name = "RSA Cipher (Kütüphaneli)"
        self.description = "RSA - Asimetrik şifreleme algoritması\nKullanım: Anahtar dağıtımı (Hibrit Şifreleme) için kullanılır."
        self.key_type = "keypair"  
        self.min_key_length = 1
        self.max_key_length = 10000
        self.key_description = "RSA anahtar çifti (public_key:private_key formatında veya 'generate' ile otomatik üretim)"
        self.supports_binary = True

    # --- Anahtar Yönetimi ---

    def generate_key_pair(self, key_size: int = None) -> Tuple[bytes, bytes]:
        """RSA anahtar çifti oluşturur (Private ve Public PEM formatında)."""
        if key_size is None:
            key_size = self.DEFAULT_KEY_SIZE
        
        if key_size not in self.SUPPORTED_KEY_SIZES:
            raise ValueError(f"Desteklenmeyen anahtar boyutu: {key_size}")
        
        # RSA anahtar çifti oluştur
        private_key = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # PEM formatına dönüştür
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem

    def _parse_key_string(self, key_string: str) -> Tuple[bytes, bytes, Optional[int]]:
        """Anahtar string'ini parse eder. Returns: (public_pem, private_pem, key_size)"""
        
        public_pem = None
        private_pem = None
        key_size = None

        if key_string.lower() == "generate" or not key_string:
            # Otomatik anahtar üretimi
            private_pem, public_pem = self.generate_key_pair()
            key_size = self.DEFAULT_KEY_SIZE
            return public_pem, private_pem, key_size
        
        # public_key:private_key formatı
        parts = key_string.split(':', 1)
        if len(parts) != 2:
            raise ValueError("RSA anahtar formatı: 'public_key:private_key' veya 'generate'")
        
        public_pem = parts[0].encode()
        private_pem = parts[1].encode()
        
        # PEM formatını kontrol et ve key size'ı al
        try:
            pub_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
            serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
            key_size = pub_key.key_size
        except Exception as e:
            raise ValueError(f"Geçersiz RSA anahtar içeriği: {str(e)}")
        
        return public_pem, private_pem, key_size

    # --- Şifreleme/Deşifreleme Çekirdek Metotları ---

    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Veriyi RSA ile şifreler (Public Key gereklidir).
        
        ⚠️ ÖNEMLİ: RSA ile doğrudan büyük veri/metin şifrelemek verimsizdir.
        Bu metodun anahtar (seans anahtarı) taşıma için kullanılması önerilir.
        """
        if len(data) > 512:
            Logger.warning(f"RSA ile büyük veri ({len(data)} byte) şifreleniyor. Bu işlem yavaştır. Hibrit yöntemi (AES+RSA) önerilir.", "RSACipher")
        
        try:
            # Public key'i ayır (key string'i "pub:priv" formatında gelebilir veya "generate" olabilir)
            public_pem = None
            if ':' in key or key.lower() == 'generate' or not key:
                public_pem, _, _ = self._parse_key_string(key)
            else:
                # Base64 PEM desteği (GUI'den gelirse)
                key_bytes = key.encode() if isinstance(key, str) else key
                if not key_bytes.startswith(b'-----'):
                    try:
                        decoded = base64.b64decode(key_bytes)
                        if decoded.startswith(b'-----'):
                            key_bytes = decoded
                    except:
                        pass
                public_pem = key_bytes
            
            public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
            
            # Maksimum şifreleyebileceği veri boyutu (OAEP+SHA256 için)
            key_size_bytes = public_key.key_size // 8
            max_chunk_size = key_size_bytes - 2 * self.OAEP_HASH_SIZE - 2
            
            if max_chunk_size <= 0:
                 raise ValueError("Anahtar boyutu OAEP padding için yetersiz.")

            # Parçalı şifreleme yapısı
            encrypted_chunks = []
            
            for i in range(0, len(data), max_chunk_size):
                chunk = data[i:i + max_chunk_size]
                
                # OAEP Padding kullanarak şifreleme
                encrypted_chunk = public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_chunks.append(encrypted_chunk)
            
            # Parçaları birleştir (Parçalı yapıyı belirtmek için)
            result = b""
            for chunk in encrypted_chunks:
                # Her parçanın başına 4 byte'lık uzunluk bilgisi ekle (Big Endian)
                length_bytes = len(chunk).to_bytes(4, byteorder='big')
                result += length_bytes + chunk
            
            return result
        
        except ValueError as e:
            raise ValueError(f"RSA Şifreleme Anahtar/Veri hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"RSA şifreleme hatası: {str(e)}")


    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        RSA ile şifrelenmiş veriyi çözer (Private Key gereklidir).
        Args: data: Şifrelenmiş veri (base64 encoded). key: RSA private key (PEM string/bytes) veya 'pub:priv' string.
        Returns: bytes: Çözülmüş veri.
        """
        try:
            # Private key'i ayır
            private_pem = None
            if ':' in key or key.lower() == 'generate' or not key:
                _, private_pem, _ = self._parse_key_string(key)
            else:
                # Base64 PEM desteği (GUI'den gelirse)
                key_bytes = key.encode() if isinstance(key, str) else key
                if not key_bytes.startswith(b'-----'):
                    try:
                        decoded = base64.b64decode(key_bytes)
                        if decoded.startswith(b'-----'):
                            key_bytes = decoded
                    except:
                        pass
                private_pem = key_bytes
            
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
            
            decrypted_chunks = []
            offset = 0
            
            # Parçalı veriyi çözme döngüsü
            while offset < len(data):
                # 4 byte uzunluk bilgisi oku
                if offset + 4 > len(data):
                    raise ValueError("Parçalı veri formatı bozuk: Eksik uzunluk bilgisi.")
                chunk_length = int.from_bytes(data[offset:offset+4], byteorder='big')
                offset += 4
                
                # Parçayı oku
                if offset + chunk_length > len(data):
                    raise ValueError("Parçalı veri formatı bozuk: Eksik veri parçası.")
                chunk = data[offset:offset + chunk_length]
                offset += chunk_length
                
                # RSA ile deşifreleme
                decrypted_chunk = private_key.decrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_chunks.append(decrypted_chunk)
            
            return b"".join(decrypted_chunks)
        
        except ValueError as e:
            # Geçersiz anahtar, padding hatası veya format hatası
            raise ValueError(f"RSA Çözme hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"RSA çözme hatası: {str(e)}")

    # --- Anahtar Dağıtım Yardımcı Metotları (Proje Odaklı) ---

    def encrypt_symmetric_key(self, symmetric_key: bytes, public_key_pem: bytes) -> bytes:
        """Simetrik anahtarı RSA Public Key ile şifreler."""
        return self.encrypt(symmetric_key, public_key_pem.decode() if isinstance(public_key_pem, bytes) else public_key_pem)

    def decrypt_symmetric_key(self, encrypted_key: bytes, private_key_pem: bytes) -> bytes:
        """RSA Private Key ile şifrelenmiş simetrik anahtarı çözer."""
        return self.decrypt(encrypted_key, private_key_pem.decode() if isinstance(private_key_pem, bytes) else private_key_pem)

    def validate_key(self, key: str) -> bool:
        """RSA anahtarının geçerli olup olmadığını kontrol eder."""
        try:
            if key.lower() == "generate" or not key:
                return True
            self._parse_key_string(key)
            return True
        except ValueError:
            return False
        except Exception:
            return False