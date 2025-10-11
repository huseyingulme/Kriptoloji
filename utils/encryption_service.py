"""
Şifreleme servisi
Tüm şifreleme işlemlerini yönetir
"""

import sys
import os
from typing import Union, Dict, Any, List
import base64
from datetime import datetime

# Üst dizindeki modülleri import edebilmek için path'e ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from algorithms import get_algorithm, get_available_algorithms, get_algorithm_info


class EncryptionService:
    """
    Şifreleme işlemlerini yöneten ana servis sınıfı
    """
    
    def __init__(self):
        """Şifreleme servisini başlatır"""
        self.available_algorithms = get_available_algorithms()
    
    def encrypt_text(self, text: str, algorithm: str, **params) -> Dict[str, Any]:
        """
        Metni şifreler
        
        Args:
            text: Şifrelenecek metin
            algorithm: Kullanılacak algoritma
            **params: Algoritmaya özel parametreler
            
        Returns:
            Şifreleme sonucu
        """
        try:
            # Algoritmayı al
            cipher = get_algorithm(algorithm)
            
            # Metni şifrele
            encrypted_text = cipher.encrypt(text, **params)
            
            return {
                'success': True,
                'encrypted_data': encrypted_text,
                'algorithm': algorithm,
                'params': params,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'algorithm': algorithm,
                'params': params
            }
    
    def decrypt_text(self, encrypted_text: str, algorithm: str, **params) -> Dict[str, Any]:
        """
        Şifrelenmiş metni çözer
        
        Args:
            encrypted_text: Şifrelenmiş metin
            algorithm: Kullanılacak algoritma
            **params: Algoritmaya özel parametreler
            
        Returns:
            Çözme sonucu
        """
        try:
            # Algoritmayı al
            cipher = get_algorithm(algorithm)
            
            # Metni çöz
            decrypted_text = cipher.decrypt(encrypted_text, **params)
            
            return {
                'success': True,
                'decrypted_data': decrypted_text,
                'algorithm': algorithm,
                'params': params,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'algorithm': algorithm,
                'params': params
            }
    
    def encrypt_file(self, file_data: bytes, algorithm: str, **params) -> Dict[str, Any]:
        """
        Dosyayı şifreler
        
        Args:
            file_data: Şifrelenecek dosya verisi
            algorithm: Kullanılacak algoritma
            **params: Algoritmaya özel parametreler
            
        Returns:
            Şifreleme sonucu
        """
        try:
            # Algoritmayı al
            cipher = get_algorithm(algorithm)
            
            # Dosya verisini string'e çevir (base64 encode)
            file_data_str = base64.b64encode(file_data).decode('utf-8')
            
            # Şifrele
            encrypted_data = cipher.encrypt(file_data_str, **params)
            
            # Base64 encode et
            encrypted_bytes = base64.b64encode(encrypted_data.encode('utf-8'))
            
            return {
                'success': True,
                'encrypted_data': encrypted_bytes.decode('utf-8'),
                'algorithm': algorithm,
                'params': params,
                'original_size': len(file_data),
                'encrypted_size': len(encrypted_bytes),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'algorithm': algorithm,
                'params': params
            }
    
    def decrypt_file(self, encrypted_data: str, algorithm: str, **params) -> Dict[str, Any]:
        """
        Şifrelenmiş dosyayı çözer
        
        Args:
            encrypted_data: Şifrelenmiş dosya verisi (base64 encoded)
            algorithm: Kullanılacak algoritma
            **params: Algoritmaya özel parametreler
            
        Returns:
            Çözme sonucu
        """
        try:
            # Algoritmayı al
            cipher = get_algorithm(algorithm)
            
            # Base64 decode et
            encrypted_bytes = base64.b64decode(encrypted_data)
            encrypted_str = encrypted_bytes.decode('utf-8')
            
            # Çöz
            decrypted_str = cipher.decrypt(encrypted_str, **params)
            
            # Orijinal dosya verisini al
            decrypted_data = base64.b64decode(decrypted_str)
            
            return {
                'success': True,
                'file_data': base64.b64encode(decrypted_data).decode('utf-8'),
                'algorithm': algorithm,
                'params': params,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'algorithm': algorithm,
                'params': params
            }
    
    def get_available_algorithms(self) -> List[str]:
        """
        Mevcut algoritmaları döndürür
        
        Returns:
            Algoritma adları listesi
        """
        return self.available_algorithms.copy()
    
    def get_algorithm_info(self, algorithm: str) -> Dict[str, Any]:
        """
        Algoritma hakkında bilgi döndürür
        
        Args:
            algorithm: Algoritma adı
            
        Returns:
            Algoritma bilgileri
        """
        try:
            return get_algorithm_info(algorithm)
        except ValueError as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def validate_algorithm_params(self, algorithm: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Algoritma parametrelerini doğrular
        
        Args:
            algorithm: Algoritma adı
            params: Kontrol edilecek parametreler
            
        Returns:
            Doğrulama sonucu
        """
        try:
            cipher = get_algorithm(algorithm)
            is_valid = cipher.validate_params(params)
            
            return {
                'success': True,
                'valid': is_valid,
                'required_params': cipher.required_params,
                'missing_params': [p for p in cipher.required_params if p not in params]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


# Global servis instance'ı
encryption_service = EncryptionService()
