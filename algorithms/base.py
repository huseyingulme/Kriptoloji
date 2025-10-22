from abc import ABC, abstractmethod
from typing import Union, Dict, Any
import re


class TextEncryptionAlgorithm(ABC):
    def __init__(self, name: str):
        self.name = name
        self.required_params = []
    
    @abstractmethod
    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        """
        Metni şifreler
        
        Args:
            data: Şifrelenecek veri
            **kwargs: Algoritmaya özel parametreler
            
        Returns:
            Şifrelenmiş veri
        """
        pass
    
    @abstractmethod
    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        """
        Şifrelenmiş metni çözer
        
        Args:
            data: Şifrelenmiş veri
            **kwargs: Algoritmaya özel parametreler
            
        Returns:
            Çözülmüş veri
        """
        pass
    
    def validate_params(self, params: Dict[str, Any]) -> bool:
        """
        Gerekli parametrelerin varlığını kontrol eder
        
        Args:
            params: Kontrol edilecek parametreler
            
        Returns:
            Tüm gerekli parametreler varsa True
        """
        for param in self.required_params:
            if param not in params:
                return False
        return True
    
    def _prepare_text(self, text: str) -> str:
        """
        Metni şifreleme için hazırlar
        - Sadece alfabetik karakterleri tutar
        - Büyük harfe çevirir
        - Boşlukları ve özel karakterleri kaldırır
        
        Args:
            text: Hazırlanacak metin
            
        Returns:
            Hazırlanmış metin
        """
        # Sadece alfabetik karakterleri tut ve büyük harfe çevir
        processed = re.sub(r'[^A-Za-z]', '', text.upper())
        return processed
    
    def get_info(self) -> Dict[str, Any]:
        """
        Algoritma hakkında bilgi döndürür
        
        Returns:
            Algoritma bilgileri
        """
        return {
            'name': self.name,
            'required_params': self.required_params,
            'description': f'{self.name} şifreleme algoritması'
        }
    
    def __str__(self) -> str:
        """String temsili"""
        return f"{self.name} Encryption Algorithm"
    
    def __repr__(self) -> str:
        """String temsili"""
        return f"<{self.__class__.__name__}(name='{self.name}')>"
