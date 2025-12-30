"""
ECC Cipher - Elliptic Curve Cryptography (Key Agreement)

Bu modül, Elliptic Curve Diffie-Hellman (ECDH) protokolünü 
güvenli anahtar anlaşması için sağlar.

🔒 KRİPTO FELSEFESİ:
"ECC, anahtar anlaşması (Key Agreement) amacıyla kullanılır."
- RSA gibi doğrudan şifreleme yerine, taraflar arasında paylaşılan 
  bir gizli anahtar (Shared Secret) üretir.
- Bu paylaşılan gizli anahtar, AES seans anahtarı olarak türetilir.
"""

from algorithms.BaseCipher import BaseCipher
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Optional
import base64

class ECCCipher(BaseCipher):
    """
    ECC (Elliptic Curve Diffie-Hellman) Key Agreement Sınıfı.
    """

    def __init__(self):
        super().__init__()
        self.name = "ECC (ECDH) Key Agreement"
        self.description = "Elliptic Curve Diffie-Hellman - Güvenli anahtar anlaşma protokolü"
        self.key_type = "ecc_keypair"
        self.supports_binary = True
        self.curve = ec.SECP256R1() # NIST P-256

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """ECC anahtar çifti oluşturur (Private ve Public PEM)."""
        private_key = ec.generate_private_key(self.curve, default_backend())
        public_key = private_key.public_key()

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

    def get_shared_secret(self, private_pem: bytes, peer_public_pem: bytes) -> bytes:
        """
        Paylaşılan gizli anahtarı (Shared Secret) hesaplar ve ondan 
        AES için uygun bir anahtar türetir.
        """
        private_key = serialization.load_pem_private_key(
            private_pem, password=None, backend=default_backend()
        )
        peer_public_key = serialization.load_pem_public_key(
            peer_public_pem, backend=default_backend()
        )

        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Paylaşılan gizli anahtarı SHA-256 ile özetleyerek 32-byte (AES-256) anahtara dönüştür
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_key)
        return digest.finalize()

    # BaseCipher uyumluluğu için boş metodlar
    def encrypt(self, data: bytes, key: str) -> bytes:
        raise NotImplementedError("ECC doğrudan şifreleme için değil, anahtar anlaşması içindir.")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        ECC için 'deşifreleme' işlemi aslında Shared Secret (Paylaşılan Gizli) türetimidir.
        Manuel araçlarda: 
        - data: Karşı tarafın (istemcinin) ephemeral public key'i (B64 veya PEM)
        - key: Sunucunun private key'i (PEM veya B64-PEM)
        Returns: bytes (Base64'lü 32-byte anahtar)
        """
        try:
            # 1. Private Key Hazırlığı (Sunucu)
            private_pem = key.strip().encode('utf-8') if isinstance(key, str) else key
            
            # Eğer Private Key Base64-PEM ise (GUI'den gelmiş olabilir)
            if not private_pem.startswith(b"-----"):
                try:
                    import base64
                    decoded_priv = base64.b64decode(private_pem)
                    if b"-----BEGIN" in decoded_priv:
                        private_pem = decoded_priv
                except:
                    pass

            # 2. Public Key Hazırlığı (İstemci - data içinden)
            peer_public_pem = data
            
            # Eğer Public Key Base64-PEM veya Ham DER-Base64 ise
            if not peer_public_pem.startswith(b"-----"):
                try:
                    import base64
                    decoded_pub = base64.b64decode(peer_public_pem)
                    
                    # Eğer Base64-PEM ise (başlangıcı decode edildiğinde PEM olur)
                    if b"-----BEGIN" in decoded_pub:
                        peer_public_pem = decoded_pub
                    else:
                        # Eğer ham DER ise PEM'e çevir
                        try:
                            peer_public_key = serialization.load_der_public_key(decoded_pub, backend=default_backend())
                            peer_public_pem = peer_public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                        except:
                            # Sadece ham B64 ama load_der başarısız, get_shared_secret deneyecek
                            pass
                except:
                    pass

            shared_secret = self.get_shared_secret(private_pem, peer_public_pem)
            return shared_secret
        except Exception as e:
            raise ValueError(f"ECC Key Agreement hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        return True # Basitleştirilmiş kontrol
