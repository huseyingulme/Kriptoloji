from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
from typing import Tuple, Optional
from shared.advanced_logger import advanced_logger

class DigitalSignature:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self._generate_key_pair()
    
    def _generate_key_pair(self):
        try:
            from config import config_manager
            key_dir = config_manager.config_dir / "keys"
            key_dir.mkdir(parents=True, exist_ok=True)
            
            private_key_file = key_dir / "private_key.pem"
            public_key_file = key_dir / "public_key.pem"
            
            if private_key_file.exists() and public_key_file.exists():
                with open(private_key_file, 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                
                with open(public_key_file, 'rb') as f:
                    self.public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
            else:
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                self.public_key = self.private_key.public_key()
                
                with open(private_key_file, 'wb') as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                
                with open(public_key_file, 'wb') as f:
                    f.write(self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                
                advanced_logger.info("Yeni dijital imza anahtar çifti oluşturuldu", "DigitalSignature")
        except Exception as e:
            advanced_logger.error(f"Anahtar çifti oluşturma/yükleme hatası: {str(e)}", "DigitalSignature")
            raise
    
    def sign(self, data: bytes) -> str:
        try:
            signature = self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8')
            
            advanced_logger.audit("SYSTEM", "file_signed", {"data_size": len(data)})
            
            return signature_b64
        except Exception as e:
            advanced_logger.error(f"Dosya imzalama hatası: {str(e)}", "DigitalSignature")
            raise
    
    def verify(self, data: bytes, signature: str) -> bool:
        try:
            signature_bytes = base64.urlsafe_b64decode(signature.encode('utf-8'))
            
            self.public_key.verify(
                signature_bytes,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            advanced_logger.audit("SYSTEM", "signature_verified", {"data_size": len(data)})
            
            return True
        except Exception as e:
            advanced_logger.warning(f"İmza doğrulama hatası: {str(e)}", "DigitalSignature")
            return False
    
    def get_public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

