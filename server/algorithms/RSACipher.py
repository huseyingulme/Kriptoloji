"""
RSA Cipher - Asimetrik Şifreleme Algoritması

RSA (Rivest-Shamir-Adleman) asimetrik şifreleme algoritması.
Bu implementasyonda RSA, simetrik şifreleme yerine anahtar dağıtımı 
amacıyla kullanılmaktadır.

ÖNEMLİ: RSA, veri şifreleme için değil, simetrik anahtarları güvenli 
bir şekilde iletmek için kullanılır.
"""

from server.algorithms.BaseCipher import BaseCipher
from typing import Union, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
import base64


class RSACipher(BaseCipher):
    """
    RSA şifreleme algoritması.
    
    Bu implementasyonda RSA, simetrik anahtarları (AES/DES anahtarları)
    güvenli bir şekilde iletmek için kullanılır.
    """

    DEFAULT_KEY_SIZE = 2048  # RSA anahtar boyutu (bit)
    SUPPORTED_KEY_SIZES = [1024, 2048, 3072, 4096]

    def __init__(self):
        super().__init__()
        self.name = "RSA Cipher"
        self.description = "RSA - Asimetrik şifreleme algoritması\n\nKullanım: Anahtar dağıtımı için kullanılır (simetrik anahtarları şifrelemek için)\n\nRSA Adımları:\n1. İki büyük asal sayı seç (p, q)\n2. n = p * q hesapla\n3. φ(n) = (p-1)(q-1) hesapla\n4. e seç (1 < e < φ(n), e ile φ(n) aralarında asal)\n5. d hesapla (e * d ≡ 1 mod φ(n))\n6. Public Key: (e, n)\n7. Private Key: (d, n)\n\nŞifreleme: C = M^e mod n\nÇözme: M = C^d mod n"
        self.key_type = "keypair"  # RSA için public/private key çifti gerekir
        self.min_key_length = 1
        self.max_key_length = 10000
        self.key_description = "RSA anahtar çifti (public_key:private_key formatında veya 'generate' ile otomatik üretim)"
        self.supports_binary = True

    def generate_key_pair(self, key_size: int = None) -> Tuple[bytes, bytes]:
        """
        RSA anahtar çifti oluşturur.
        
        Args:
            key_size: Anahtar boyutu (bit cinsinden). Varsayılan: 2048
            
        Returns:
            Tuple[bytes, bytes]: (private_key, public_key) PEM formatında
        """
        if key_size is None:
            key_size = self.DEFAULT_KEY_SIZE
        
        if key_size not in self.SUPPORTED_KEY_SIZES:
            raise ValueError(f"Desteklenmeyen anahtar boyutu: {key_size}. Desteklenen: {self.SUPPORTED_KEY_SIZES}")
        
        # RSA anahtar çifti oluştur
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standart RSA public exponent
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

    def _parse_key_string(self, key_string: str) -> Tuple[bytes, bytes]:
        """
        Anahtar string'ini parse eder.
        
        Format: "public_key:private_key" veya "generate" (otomatik üretim)
        
        Args:
            key_string: Anahtar string'i
            
        Returns:
            Tuple[bytes, bytes]: (public_key, private_key) PEM formatında
        """
        if key_string.lower() == "generate" or not key_string:
            # Otomatik anahtar üretimi
            private_pem, public_pem = self.generate_key_pair()
            return public_pem, private_pem
        
        # public_key:private_key formatı
        parts = key_string.split(':', 1)
        if len(parts) != 2:
            raise ValueError("RSA anahtar formatı: 'public_key:private_key' veya 'generate'")
        
        public_pem = parts[0].encode() if isinstance(parts[0], str) else parts[0]
        private_pem = parts[1].encode() if isinstance(parts[1], str) else parts[1]
        
        # PEM formatını kontrol et
        try:
            serialization.load_pem_public_key(public_pem, backend=default_backend())
            serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
        except Exception as e:
            raise ValueError(f"Geçersiz RSA anahtar formatı: {str(e)}")
        
        return public_pem, private_pem

    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Veriyi RSA ile şifreler.
        
        NOT: RSA, büyük verileri doğrudan şifrelemek için uygun değildir.
        Bu implementasyonda RSA, simetrik anahtarları şifrelemek için kullanılır.
        
        Args:
            data: Şifrelenecek veri (bytes) - Maksimum boyut anahtar boyutuna bağlı
            key: RSA public key (PEM formatında)
            
        Returns:
            bytes: Şifrelenmiş veri (base64 encoded)
        """
        try:
            # Public key'i yükle
            if isinstance(key, str):
                if ':' in key:
                    # public_key:private_key formatından sadece public key'i al
                    public_pem, _ = self._parse_key_string(key)
                else:
                    public_pem = key.encode() if not key.startswith('-----') else key.encode()
            else:
                public_pem = key
            
            public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
            
            # RSA ile şifreleme (OAEP padding kullan)
            # RSA maksimum şifreleyebileceği veri boyutu: (key_size / 8) - 2 * hash_size - 2
            # 2048-bit RSA için: 256 - 64 - 2 = 190 byte
            max_chunk_size = (public_key.key_size // 8) - 2 * 32 - 2  # SHA256 için
            
            if len(data) > max_chunk_size:
                # Büyük verileri parçalara böl
                encrypted_chunks = []
                for i in range(0, len(data), max_chunk_size):
                    chunk = data[i:i + max_chunk_size]
                    encrypted_chunk = public_key.encrypt(
                        chunk,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    encrypted_chunks.append(encrypted_chunk)
                
                # Parçaları birleştir (her parçanın başına uzunluk bilgisi ekle)
                result = b""
                for chunk in encrypted_chunks:
                    length_bytes = len(chunk).to_bytes(4, byteorder='big')
                    result += length_bytes + chunk
                
                return base64.b64encode(result)
            else:
                # Küçük verileri direkt şifrele
                encrypted_data = public_key.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return base64.b64encode(encrypted_data)
        
        except ValueError as e:
            raise ValueError(f"Anahtar hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"RSA şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        RSA ile şifrelenmiş veriyi çözer.
        
        Args:
            data: Şifrelenmiş veri (base64 encoded)
            key: RSA private key (PEM formatında) veya "public_key:private_key" formatı
            
        Returns:
            bytes: Çözülmüş veri
        """
        try:
            # Private key'i yükle
            if isinstance(key, str):
                if ':' in key:
                    # public_key:private_key formatından private key'i al
                    _, private_pem = self._parse_key_string(key)
                else:
                    private_pem = key.encode() if not key.startswith('-----') else key.encode()
            else:
                private_pem = key
            
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
            
            # Base64 decode
            encrypted_data = base64.b64decode(data)
            
            # Parçalı veri kontrolü (ilk 4 byte uzunluk bilgisi olabilir)
            if len(encrypted_data) > 4:
                # Parçalı veri olabilir, kontrol et
                first_length = int.from_bytes(encrypted_data[:4], byteorder='big')
                if first_length < len(encrypted_data) and first_length > 0:
                    # Parçalı veri
                    decrypted_chunks = []
                    offset = 0
                    while offset < len(encrypted_data):
                        if offset + 4 > len(encrypted_data):
                            break
                        chunk_length = int.from_bytes(encrypted_data[offset:offset+4], byteorder='big')
                        offset += 4
                        if offset + chunk_length > len(encrypted_data):
                            break
                        chunk = encrypted_data[offset:offset + chunk_length]
                        offset += chunk_length
                        
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
            
            # Tek parça veri
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_data
        
        except ValueError as e:
            raise ValueError(f"Anahtar hatası: {str(e)}")
        except Exception as e:
            raise Exception(f"RSA çözme hatası: {str(e)}")

    def encrypt_symmetric_key(self, symmetric_key: bytes, public_key_pem: bytes) -> bytes:
        """
        Simetrik anahtarı RSA ile şifreler (anahtar dağıtımı için).
        
        Args:
            symmetric_key: Şifrelenecek simetrik anahtar (AES/DES anahtarı)
            public_key_pem: RSA public key (PEM formatında)
            
        Returns:
            bytes: Şifrelenmiş simetrik anahtar (base64 encoded)
        """
        return self.encrypt(symmetric_key, public_key_pem.decode() if isinstance(public_key_pem, bytes) else public_key_pem)

    def decrypt_symmetric_key(self, encrypted_key: bytes, private_key_pem: bytes) -> bytes:
        """
        RSA ile şifrelenmiş simetrik anahtarı çözer.
        
        Args:
            encrypted_key: Şifrelenmiş simetrik anahtar (base64 encoded)
            private_key_pem: RSA private key (PEM formatında)
            
        Returns:
            bytes: Çözülmüş simetrik anahtar
        """
        return self.decrypt(encrypted_key, private_key_pem.decode() if isinstance(private_key_pem, bytes) else private_key_pem)

    def validate_key(self, key: str) -> bool:
        """RSA anahtarının geçerli olup olmadığını kontrol eder."""
        try:
            if key.lower() == "generate" or not key:
                return True
            self._parse_key_string(key)
            return True
        except (ValueError, Exception):
            return False

