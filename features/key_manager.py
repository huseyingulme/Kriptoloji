import hashlib
import base64
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import time
from shared.advanced_logger import advanced_logger

class KeyManager:
    def __init__(self):
        self.master_key = None
        self.encrypted_keys = {}
        self._load_master_key()
    
    def _load_master_key(self):
        try:
            from config import config_manager
            key_file = config_manager.config_dir / "master.key"
            
            if key_file.exists():
                with open(key_file, 'rb') as f:
                    self.master_key = f.read()
            else:
                self.master_key = Fernet.generate_key()
                key_file.parent.mkdir(parents=True, exist_ok=True)
                with open(key_file, 'wb') as f:
                    f.write(self.master_key)
        except Exception as e:
            advanced_logger.warning(f"Master key yükleme hatası, yeni key oluşturuluyor: {str(e)}", "KeyManager")
            self.master_key = Fernet.generate_key()
    
    def generate_strong_key(self, length: int = 32) -> str:
        return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8')
    
    def encrypt_key(self, key: str, key_id: str) -> str:
        try:
            fernet = Fernet(self.master_key)
            encrypted = fernet.encrypt(key.encode('utf-8'))
            self.encrypted_keys[key_id] = encrypted
            return base64.urlsafe_b64encode(encrypted).decode('utf-8')
        except Exception as e:
            advanced_logger.error(f"Anahtar şifreleme hatası: {str(e)}", "KeyManager")
            raise
    
    def decrypt_key(self, encrypted_key: str, key_id: str) -> str:
        try:
            if key_id in self.encrypted_keys:
                encrypted = self.encrypted_keys[key_id]
            else:
                encrypted = base64.urlsafe_b64decode(encrypted_key.encode('utf-8'))
            
            fernet = Fernet(self.master_key)
            decrypted = fernet.decrypt(encrypted)
            return decrypted.decode('utf-8')
        except Exception as e:
            advanced_logger.error(f"Anahtar çözme hatası: {str(e)}", "KeyManager")
            raise
    
    def share_key(self, key: str, recipient_public_key: Optional[str] = None) -> Dict[str, Any]:
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        share_data = {
            "key_hash": key_hash,
            "encrypted_key": self.encrypt_key(key, key_hash),
            "timestamp": time.time()
        }
        
        advanced_logger.audit("SYSTEM", "key_shared", {"key_hash": key_hash})
        
        return share_data
    
    def import_shared_key(self, share_data: Dict[str, Any]) -> str:
        try:
            key_hash = share_data.get("key_hash")
            encrypted_key = share_data.get("encrypted_key")
            
            if not key_hash or not encrypted_key:
                raise ValueError("Geçersiz paylaşım verisi")
            
            key = self.decrypt_key(encrypted_key, key_hash)
            
            advanced_logger.audit("SYSTEM", "key_imported", {"key_hash": key_hash})
            
            return key
        except Exception as e:
            advanced_logger.error(f"Paylaşılan anahtar içe aktarma hatası: {str(e)}", "KeyManager")
            raise

