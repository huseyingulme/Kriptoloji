"""
Key Management Module - Güvenli Anahtar Üretimi ve Dağıtımı

Bu modül, projedeki tüm şifreleme algoritmaları için merkezi anahtar yönetimini sağlar.
Akademik gereksinimlere uygun olarak:
1. Oturum anahtarları (session keys) güvenli bir şekilde üretilir.
2. Simetrik anahtarların güvenli paylaşımı için RSA/DH mekanizmaları kullanılır.
"""

import os
import base64
from typing import Tuple, Optional, Dict
from algorithms.RSACipher import RSACipher
from shared.utils import Logger

class KeyManagement:
    """
    Merkezi Anahtar Yönetim Sınıfı.
    """
    
    def __init__(self):
        self.rsa_cipher = RSACipher()
        self._server_key_pair: Optional[Tuple[bytes, bytes]] = None
        self._server_ecc_key_pair: Optional[Tuple[bytes, bytes]] = None
        self._ensure_server_keys()

    def _ensure_server_keys(self):
        """Sunucu RSA anahtarlarının varlığını garanti eder."""
        if not self._server_key_pair:
            try:
                # 2048-bit RSA anahtar çifti oluştur
                self._server_key_pair = self.rsa_cipher.generate_key_pair(key_size=2048)
                Logger.info("Sunucu RSA anahtar çifti başarıyla oluşturuldu.", "KeyManagement")
            except Exception as e:
                Logger.error(f"Anahtar çifti oluşturma hatası: {str(e)}", "KeyManagement")
                raise

    def generate_session_key(self, length: int = 32) -> bytes:
        """
        Güvenli bir oturum anahtarı üretir.
        
        Args:
            length (int): Anahtar boyutu (AES-256 için 32 byte varsayılan)
        Returns:
            bytes: Üretilen rastgele anahtar
        """
        return os.urandom(length)

    def encrypt_key_for_distribution(self, session_key: bytes, public_key_pem: bytes = None) -> bytes:
        """
        Oturum anahtarını iletim için RSA ile şifreler.
        
        Args:
            session_key (bytes): Şifrelenecek oturum anahtarı
            public_key_pem (bytes): Hedefin public key'i (None ise sunucununkini kullanır)
        Returns:
            bytes: Şifrelenmiş anahtar (Base64)
        """
        if public_key_pem is None:
            public_key_pem = self._server_key_pair[1]
        
        return self.rsa_cipher.encrypt_symmetric_key(session_key, public_key_pem)

    def decrypt_received_key(self, encrypted_key_b64: bytes, private_key_pem: bytes = None) -> bytes:
        """
        Gelen şifreli anahtarı çözer.
        
        Args:
            encrypted_key_b64 (bytes): Base64 şifreli anahtar
            private_key_pem (bytes): Çözücü private key (None ise sunucununkini kullanır)
        Returns:
            bytes: Çözülmüş orijinal anahtar
        """
        if private_key_pem is None:
            private_key_pem = self._server_key_pair[0]
            
        return self.rsa_cipher.decrypt_symmetric_key(encrypted_key_b64, private_key_pem)

    def get_server_public_key(self) -> bytes:
        """Sunucu RSA public key'ini döndürür."""
        return self._server_key_pair[1]

    def get_server_private_key(self) -> bytes:
        """Sunucu RSA private key'ini döndürür (Admin panel için)."""
        return self._server_key_pair[0]

    # --- ECC Support (Added for modern key agreement) ---

    def generate_ecc_key_pair(self) -> Tuple[bytes, bytes]:
        """ECC (ECDH) anahtar çifti oluşturur (Persist eder)."""
        if self._server_ecc_key_pair:
            return self._server_ecc_key_pair
            
        from algorithms.ECCCipher import ECCCipher
        ecc = ECCCipher()
        self._server_ecc_key_pair = ecc.generate_key_pair()
        return self._server_ecc_key_pair

    def derive_shared_secret(self, private_pem: bytes, peer_public_pem: bytes) -> bytes:
        """ECDH ile ortak gizli anahtar türetir."""
        from algorithms.ECCCipher import ECCCipher
        ecc = ECCCipher()
        return ecc.get_shared_secret(private_pem, peer_public_pem)

# Global instance for easy access
key_manager = KeyManagement()
