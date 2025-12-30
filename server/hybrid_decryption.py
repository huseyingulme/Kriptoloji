"""
Hibrit Şifreleme Çözme Yöneticisi - Sunucu Tarafı

Bu modül, hibrit şifreleme ile gelen paketleri çözer:
1. RSA ile şifrelenmiş simetrik anahtarı çözer
2. AES/DES ile şifrelenmiş mesajı çözer
3. Düz metni döndürür
"""

import json
import base64
from typing import Dict, Any, Optional, Union
from algorithms.AESCipher import AESCipher
from algorithms.DESCipher import DESCipher
from algorithms.AESManual import AESManual
from algorithms.DESManual import DESManual
from algorithms.RSACipher import RSACipher
from algorithms.ECCCipher import ECCCipher
from security.key_management import key_manager
from shared.utils import Logger


class HybridDecryptionManager:
    """
    Hibrit şifreleme çözme yöneticisi - Sunucu tarafı.
    
    Bu sınıf, hibrit şifreleme ile gelen paketleri çözer:
    1. Paketi parse eder
    2. RSA ile şifrelenmiş simetrik anahtarı çözer
    3. Simetrik anahtar ile mesajı çözer
    4. Düz metni döndürür
    """

    def __init__(self, key_manager_instance=None, *args, **kwargs):
        """
        Hibrit çözme yöneticisini başlatır.
        """
        self.key_manager = key_manager_instance or key_manager
        self.rsa_cipher = RSACipher()
        self.ecc_cipher = ECCCipher()
        self.aes_cipher = AESCipher()
        self.des_cipher = DESCipher()
        self.aes_manual = AESManual()
        self.des_manual = DESManual()
        self._server_ecc_private_key: Optional[bytes] = None

    def parse_hybrid_packet(self, packet: bytes) -> Dict[str, Any]:
        """
        Hibrit şifreleme paketini parse eder.
        
        Args:
            packet: JSON paketi (bytes)
            
        Returns:
            Dict: Parse edilmiş paket bilgileri
        """
        try:
            try:
                packet_json = packet.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Paket UTF-8 formatında değil. Hibrit şifreleme için geçerli bir JSON paketi gereklidir.")
                
            try:
                packet_data = json.loads(packet_json)
            except json.JSONDecodeError:
                raise ValueError("Paket geçerli bir JSON formatında değil. Hibrit şifreleme paketi bozulmuş olabilir.")
            
            if packet_data.get('type') != 'HYBRID_ENCRYPT':
                raise ValueError("Geçersiz paket tipi")
            
            return {
                'algorithm': packet_data.get('algorithm'),
                'key_type': packet_data.get('key_type', 'RSA'),
                'encrypted_key': base64.b64decode(packet_data.get('encrypted_key')),
                'encrypted_message': base64.b64decode(packet_data.get('encrypted_message')),
                'metadata': packet_data.get('metadata', {})
            }

        except Exception as e:
            Logger.error(f"Paket parse hatası: {str(e)}", "HybridDecryptionManager")
            raise

    def decrypt_message(self, packet: bytes, return_dict: bool = False) -> Union[bytes, Dict[str, Any]]:
        """
        Hibrit şifreleme paketini çözer.
        
        İşlem Adımları:
        1. Paketi parse eder
        2. RSA ile şifrelenmiş simetrik anahtarı çözer
        3. Simetrik anahtar ile mesajı çözer
        
        Args:
            packet: Hibrit şifreleme paketi (JSON bytes)
            return_dict: True ise dict döner (message, key), False ise sadece bytes
            
        Returns:
            Union[bytes, Dict]: Çözülmüş mesaj veya detaylı dict
        """
        try:
            # 1. Paketi parse et
            packet_data = self.parse_hybrid_packet(packet)
            algorithm = packet_data['algorithm']
            encrypted_key = packet_data['encrypted_key']
            encrypted_message = packet_data['encrypted_message']

            Logger.info(f"Hibrit paket parse edildi: {algorithm}", "HybridDecryptionManager")

            # 2. Anahtarı Çöz / Türet
            key_type = packet_data.get('key_type', 'RSA')
            
            if key_type == 'RSA':
                # RSA: Şifreli anahtarı çöz
                symmetric_key = self.key_manager.decrypt_received_key(encrypted_key)
            elif key_type == 'ECC':
                # ECC: Client Public Key + Server Private Key -> shared secret
                # Sunucu ECC anahtarını KeyManager'dan al
                priv_pem, _ = self.key_manager.generate_ecc_key_pair()
                
                symmetric_key = self.key_manager.derive_shared_secret(
                    priv_pem, encrypted_key # encrypted_key burada Client Public Key'dir
                )
            else:
                raise ValueError(f"Desteklenmeyen anahtar tipi: {key_type}")

            Logger.info(f"Seans anahtarı {key_type} ile hazırlandı", "HybridDecryptionManager")

            # 3. Simetrik anahtar ile mesajı çözer
            key_str = base64.b64encode(symmetric_key).decode('utf-8')
            
            if algorithm in ['aes', 'aes_manual']:
                if algorithm == 'aes_manual':
                    # Manuel AES
                    decrypted_message = self.aes_manual.decrypt(encrypted_message, key_str)
                else:
                    # Kütüphaneli AES
                    decrypted_message = self.aes_cipher.decrypt(encrypted_message, f"128:CBC:{key_str}")
            elif algorithm in ['des', 'des_manual']:
                if algorithm == 'des_manual':
                    # Manuel DES
                    decrypted_message = self.des_manual.decrypt(encrypted_message, key_str)
                else:
                    # Kütüphaneli DES
                    decrypted_message = self.des_cipher.decrypt(encrypted_message, f"CBC:{key_str}")
            else:
                raise ValueError(f"Desteklenmeyen algoritma: {algorithm}")

            Logger.info(f"Mesaj çözüldü: {len(decrypted_message)} byte", "HybridDecryptionManager")

            if return_dict:
                return {
                    'message': decrypted_message,
                    'key': symmetric_key,
                    'algorithm': algorithm
                }
            return decrypted_message

        except Exception as e:
            Logger.error(f"Hibrit çözme hatası: {str(e)}", "HybridDecryptionManager")
            raise

