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
        self.rsa_cipher = RSACipher()
        self.aes_cipher = AESCipher()
        self.des_cipher = DESCipher()
        self.aes_manual = AESManual()
        self.des_manual = DESManual()
        self.server_public_key: Optional[bytes] = None

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

    def create_hybrid_packet(self, encrypted_message: bytes, encrypted_key: bytes, 
                            algorithm: str, metadata: Dict[str, Any] = None) -> bytes:
        """
        Hibrit şifreleme paketi oluşturur.
        
        Paket formatı (JSON):
        {
            "type": "HYBRID_ENCRYPT",
            "algorithm": "aes" | "des" | "aes_manual" | "des_manual",
            "encrypted_key": "<base64_encoded_encrypted_key>",
            "encrypted_message": "<base64_encoded_encrypted_message>",
            "metadata": {...}
        }
        
        Args:
            encrypted_message: Şifrelenmiş mesaj
            encrypted_key: RSA ile şifrelenmiş simetrik anahtar
            algorithm: Kullanılan algoritma
            metadata: Ek bilgiler
            
        Returns:
            bytes: JSON paketi (bytes)
        """
        try:
            packet = {
                "type": "HYBRID_ENCRYPT",
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
                           use_manual: bool = False, metadata: Dict[str, Any] = None) -> bytes:
        """
        Mesajı şifreler ve paket oluşturur (tek adım).
        
        Args:
            message: Şifrelenecek mesaj
            algorithm: Kullanılacak algoritma
            use_manual: Manuel implementasyon kullanılacak mı?
            metadata: Ek bilgiler
            
        Returns:
            bytes: JSON paketi
        """
        encrypted_message, encrypted_key, algo_name = self.encrypt_message(message, algorithm, use_manual)
        return self.create_hybrid_packet(encrypted_message, encrypted_key, algo_name, metadata)

