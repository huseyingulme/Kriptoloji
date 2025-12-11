"""
Key Distribution Manager - RSA ile Simetrik Anahtar Dağıtımı

Bu modül, RSA kullanarak simetrik şifreleme anahtarlarını (AES/DES)
güvenli bir şekilde dağıtmak için kullanılır.

ÖNEMLİ: RSA, simetrik şifreleme yerine anahtar dağıtımı amacıyla kullanılmaktadır.
"""

import os
from typing import Tuple, Optional
from algorithms.RSACipher import RSACipher
from shared.utils import Logger


class KeyDistributionManager:
    """
    RSA ile simetrik anahtar dağıtımını yöneten sınıf.
    
    Bu sınıf, istemci-sunucu haberleşmesinde simetrik anahtarları
    güvenli bir şekilde iletmek için RSA'yı kullanır.
    """

    def __init__(self):
        """KeyDistributionManager'ı başlatır."""
        self.rsa_cipher = RSACipher()
        self.server_key_pair: Optional[Tuple[bytes, bytes]] = None
        self._generate_server_keys()

    def _generate_server_keys(self):
        """Sunucu için RSA anahtar çifti oluşturur."""
        try:
            self.server_key_pair = self.rsa_cipher.generate_key_pair(key_size=2048)
            Logger.info("Sunucu RSA anahtar çifti oluşturuldu", "KeyDistributionManager")
        except Exception as e:
            Logger.error(f"RSA anahtar çifti oluşturma hatası: {str(e)}", "KeyDistributionManager")
            raise

    def get_server_public_key(self) -> bytes:
        """
        Sunucunun public key'ini döndürür.
        
        Bu key, istemciler tarafından simetrik anahtarları şifrelemek için kullanılır.
        
        Returns:
            bytes: Public key (PEM formatında)
        """
        if not self.server_key_pair:
            self._generate_server_keys()
        return self.server_key_pair[1]  # public key

    def get_server_private_key(self) -> bytes:
        """
        Sunucunun private key'ini döndürür.
        
        Bu key, şifrelenmiş simetrik anahtarları çözmek için kullanılır.
        
        Returns:
            bytes: Private key (PEM formatında)
        """
        if not self.server_key_pair:
            self._generate_server_keys()
        return self.server_key_pair[0]  # private key

    def encrypt_symmetric_key(self, symmetric_key: bytes, public_key: bytes = None) -> bytes:
        """
        Simetrik anahtarı RSA ile şifreler.
        
        Args:
            symmetric_key: Şifrelenecek simetrik anahtar (AES/DES anahtarı)
            public_key: RSA public key (None ise sunucu public key kullanılır)
            
        Returns:
            bytes: Şifrelenmiş simetrik anahtar (base64 encoded)
        """
        try:
            if public_key is None:
                public_key = self.get_server_public_key()
            
            return self.rsa_cipher.encrypt_symmetric_key(symmetric_key, public_key)
        except Exception as e:
            Logger.error(f"Simetrik anahtar şifreleme hatası: {str(e)}", "KeyDistributionManager")
            raise

    def decrypt_symmetric_key(self, encrypted_key: bytes, private_key: bytes = None) -> bytes:
        """
        RSA ile şifrelenmiş simetrik anahtarı çözer.
        
        Args:
            encrypted_key: Şifrelenmiş simetrik anahtar (base64 encoded)
            private_key: RSA private key (None ise sunucu private key kullanılır)
            
        Returns:
            bytes: Çözülmüş simetrik anahtar
        """
        try:
            if private_key is None:
                private_key = self.get_server_private_key()
            
            return self.rsa_cipher.decrypt_symmetric_key(encrypted_key, private_key)
        except Exception as e:
            Logger.error(f"Simetrik anahtar çözme hatası: {str(e)}", "KeyDistributionManager")
            raise

    def generate_symmetric_key(self, key_size: int = 16) -> bytes:
        """
        Rastgele simetrik anahtar oluşturur.
        
        Args:
            key_size: Anahtar boyutu (byte cinsinden)
                      - AES-128 için: 16
                      - DES için: 8
            
        Returns:
            bytes: Rastgele simetrik anahtar
        """
        return os.urandom(key_size)

    def distribute_key_securely(self, symmetric_key: bytes, client_public_key: bytes = None) -> Tuple[bytes, bytes]:
        """
        Simetrik anahtarı güvenli bir şekilde dağıtır.
        
        Bu fonksiyon, hibrit şifreleme yaklaşımını kullanır:
        1. Simetrik anahtar RSA ile şifrelenir
        2. Şifrelenmiş anahtar ve public key döndürülür
        
        Args:
            symmetric_key: Dağıtılacak simetrik anahtar
            client_public_key: İstemci public key'i (None ise sunucu public key kullanılır)
            
        Returns:
            Tuple[bytes, bytes]: (encrypted_key, public_key)
        """
        try:
            if client_public_key is None:
                public_key = self.get_server_public_key()
            else:
                public_key = client_public_key
            
            encrypted_key = self.encrypt_symmetric_key(symmetric_key, public_key)
            
            return encrypted_key, public_key
        except Exception as e:
            Logger.error(f"Anahtar dağıtım hatası: {str(e)}", "KeyDistributionManager")
            raise

    def receive_encrypted_key(self, encrypted_key: bytes, private_key: bytes = None) -> bytes:
        """
        Şifrelenmiş simetrik anahtarı alır ve çözer.
        
        Args:
            encrypted_key: Şifrelenmiş simetrik anahtar
            private_key: RSA private key (None ise sunucu private key kullanılır)
            
        Returns:
            bytes: Çözülmüş simetrik anahtar
        """
        return self.decrypt_symmetric_key(encrypted_key, private_key)

