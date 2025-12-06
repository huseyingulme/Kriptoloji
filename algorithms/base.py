from abc import ABC, abstractmethod
from typing import Union, Dict, Any
import re

class TextEncryptionAlgorithm(ABC):
    def __init__(self, name: str):
        self.name = name
        self.required_params = []
    
    @abstractmethod
    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        
        pass
    
    @abstractmethod
    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        
        pass
    
    def validate_params(self, params: Dict[str, Any]) -> bool:
        
        for param in self.required_params:
            if param not in params:
                return False
        return True
    
    def _prepare_text(self, text: str) -> str:
        
        processed = re.sub(r'[^A-Za-z]', '', text.upper())
        return processed
    
    def get_info(self) -> Dict[str, Any]:
        
        return {
            'name': self.name,
            'required_params': self.required_params,
            'description': f'{self.name} şifreleme algoritması'
        }
    
    def __str__(self) -> str:
        
        return f"{self.name} Encryption Algorithm"
    
    def __repr__(self) -> str:
        
        return f"<{self.__class__.__name__}(name='{self.name}')>"
