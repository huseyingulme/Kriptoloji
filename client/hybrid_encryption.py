"""
Hibrit Şifreleme Yöneticisi - İstemci Tarafı

Bu modül, hibrit şifreleme sistemini yönetir:
1. RSA ile simetrik anahtar dağıtımı
2. AES/DES ile veri şifreleme
3. Paket oluşturma ve gönderim
"""

import os
import json
import base64
from typing import Dict, Any, Optional, Tuple
from algorithms.AESCipher import AESCipher
from algorithms.DESCipher import DESCipher
from algorithms.AESManual import AESManual
from algorithms.DESManual import DESManual
from algorithms.RSACipher import RSACipher
from algorithms.ECCCipher import ECCCipher
from shared.utils import Logger


class HybridEncryptionManager:
    """
    Hibrit şifreleme yöneticisi - İstemci tarafı.
    
    Bu sınıf, hibrit şifreleme akışını yönetir:
    1. Sunucudan RSA public key alır
    2. Simetrik anahtar (AES/DES) üretir
    3. Mesajı simetrik algoritma ile şifreler
    4. Simetrik anahtarı RSA ile şifreler
    5. Paketi oluşturur ve sunucuya gönderir
    """

    def __init__(self):
        """Hibrit şifreleme yöneticisini başlatır."""
        from algorithms.AESCipher import AESCipher
        from algorithms.DESCipher import DESCipher
        self.aes_cipher = AESCipher()
        self.des_cipher = DESCipher()
        self.aes_manual = AESManual()
        self.des_manual = DESManual()
        self.rsa_cipher = RSACipher()
        self.ecc_cipher = ECCCipher()
        self.server_public_key: Optional[bytes] = None
        self.server_ecc_public_key: Optional[bytes] = None

    def set_server_public_key(self, public_key: bytes):
        """Sunucunun RSA public key'ini ayarlar."""
        self.server_public_key = public_key
        Logger.info("Sunucu RSA public key ayarlandı", "HybridEncryptionManager")

    def generate_symmetric_key(self, algorithm: str) -> bytes:
        """
        Simetrik anahtar üretir.
        
        Args:
            algorithm: Kullanılacak algoritma ('aes', 'des', 'aes_manual', 'des_manual')
            
        Returns:
            bytes: Rastgele simetrik anahtar
        """
        if algorithm in ['aes', 'aes_manual']:
            # AES-128 için 16 byte anahtar
            return os.urandom(16)
        elif algorithm in ['des', 'des_manual']:
            # DES için 8 byte anahtar
            return os.urandom(8)
        else:
            raise ValueError(f"Desteklenmeyen algoritma: {algorithm}")

    def encrypt_message(self, message: bytes, algorithm: str, use_manual: bool = False) -> Tuple[bytes, bytes, str]:
        """
        Mesajı hibrit şifreleme ile şifreler.
        
        İşlem Adımları:
        1. Simetrik anahtar üretir
        2. Mesajı simetrik algoritma ile şifreler
        3. Simetrik anahtarı RSA ile şifreler
        
        Args:
            message: Şifrelenecek mesaj
            algorithm: Kullanılacak algoritma ('aes', 'des', 'aes_manual', 'des_manual')
            use_manual: Manuel implementasyon kullanılacak mı?
            
        Returns:
            Tuple[bytes, bytes, str]: (encrypted_message, encrypted_key, algorithm_name)
        """
        try:
            if not self.server_public_key:
                raise ValueError("Sunucu RSA public key ayarlanmamış")

            # 1. Simetrik anahtar üret
            symmetric_key = self.generate_symmetric_key(algorithm)
            Logger.info(f"Simetrik anahtar üretildi: {len(symmetric_key)} byte ({algorithm})", "HybridEncryptionManager")

            # 2. Mesajı simetrik algoritma ile şifrele
            if algorithm in ['aes', 'aes_manual']:
                if use_manual or algorithm == 'aes_manual':
                    # Manuel AES
                    key_str = base64.b64encode(symmetric_key).decode('utf-8')
                    encrypted_message = self.aes_manual.encrypt(message, key_str)
                    algo_name = 'aes_manual'
                else:
                    # Kütüphaneli AES
                    key_str = base64.b64encode(symmetric_key).decode('utf-8')
                    encrypted_message = self.aes_cipher.encrypt(message, f"128:CBC:{key_str}")
                    algo_name = 'aes'
            elif algorithm in ['des', 'des_manual']:
                if use_manual or algorithm == 'des_manual':
                    # Manuel DES
                    key_str = base64.b64encode(symmetric_key).decode('utf-8')
                    encrypted_message = self.des_manual.encrypt(message, key_str)
                    algo_name = 'des_manual'
                else:
                    # Kütüphaneli DES
                    key_str = base64.b64encode(symmetric_key).decode('utf-8')
                    encrypted_message = self.des_cipher.encrypt(message, f"CBC:{key_str}")
                    algo_name = 'des'
            else:
                raise ValueError(f"Desteklenmeyen algoritma: {algorithm}")

            Logger.info(f"Mesaj şifrelendi: {len(encrypted_message)} byte ({algo_name})", "HybridEncryptionManager")

            # 3. Simetrik anahtarı RSA ile şifrele
            encrypted_key = self.rsa_cipher.encrypt(symmetric_key, self.server_public_key.decode('utf-8'))
            Logger.info(f"Simetrik anahtar RSA ile şifrelendi: {len(encrypted_key)} byte", "HybridEncryptionManager")

            return encrypted_message, encrypted_key, algo_name

        except Exception as e:
            Logger.error(f"Hibrit şifreleme hatası: {str(e)}", "HybridEncryptionManager")
            raise

    def encrypt_message_ecc(self, message: bytes, symmetric_algo: str) -> Tuple[bytes, bytes, str]:
        """
        Mesajı ECC (ECDH) anahtar anlaşması + Simetrik şifreleme ile şifreler.
        
        İşlem Adımları:
        1. İstemci taraflı geçici (ephemeral) ECC anahtar çifti üretilir.
        2. Sunucu ECC public key'i ile ortak gizli anahtar (Shared Secret) hesaplanır.
        3. Bu gizli anahtar simetrik seans anahtarı olarak kullanılır.
        """
        if not self.server_ecc_public_key:
            raise ValueError("Sunucu ECC public key ayarlanmamış")

        # 1. Ephemeral ECC anahtar çifti üret
        priv_pem, pub_pem = self.ecc_cipher.generate_key_pair()

        # 2. Ortak gizli anahtarı (Shared Secret) hesapla -> Symmetric Key
        symmetric_key = self.ecc_cipher.get_shared_secret(priv_pem, self.server_ecc_public_key)

        # 3. Mesajı simetrik şifrele
        key_str = base64.b64encode(symmetric_key).decode('utf-8')
        
        algo_to_use = symmetric_algo.lower()
        
        if 'aes' in algo_to_use:
            if 'manual' in algo_to_use:
                encrypted_message = self.aes_manual.encrypt(message, key_str)
            else:
                encrypted_message = self.aes_cipher.encrypt(message, f"256:CBC:{key_str}")
        elif 'des' in algo_to_use:
            if 'manual' in algo_to_use:
                encrypted_message = self.des_manual.encrypt(message, key_str)
            else:
                encrypted_message = self.des_cipher.encrypt(message, f"CBC:{key_str}")
        else:
            # Varsayılan AES
            encrypted_message = self.aes_cipher.encrypt(message, f"256:CBC:{key_str}")
            
        return encrypted_message, pub_pem, symmetric_algo

    def create_hybrid_packet(self, encrypted_message: bytes, encrypted_key: bytes, 
                            algorithm: str, key_type: str = 'RSA', metadata: Dict[str, Any] = None) -> bytes:
        """
        Hibrit şifreleme paketi oluşturur.
        key_type: 'RSA' (Encrypted key) veya 'ECC' (Client Public Key)
        """
        try:
            packet = {
                "type": "HYBRID_ENCRYPT",
                "key_type": key_type,
                "algorithm": algorithm,
                "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
                "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8'),
                "metadata": metadata or {}
            }
            
            packet_json = json.dumps(packet, ensure_ascii=False)
            return packet_json.encode('utf-8')

        except Exception as e:
            Logger.error(f"Paket oluşturma hatası: {str(e)}", "HybridEncryptionManager")
            raise

    def encrypt_and_package(self, message: bytes, algorithm: str, 
                           use_manual: bool = False, metadata: Dict[str, Any] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Mesajı şifreler ve paket oluşturur.
        
        Returns:
            Tuple[bytes, bytes, bytes]: (packet_bytes, encrypted_message, encrypted_key)
        """
        encrypted_message, encrypted_key, algo_name = self.encrypt_message(message, algorithm, use_manual)
        packet = self.create_hybrid_packet(encrypted_message, encrypted_key, algo_name, key_type='RSA', metadata=metadata)
        return packet, encrypted_message, encrypted_key

