import time
from typing import Union, List, Dict, Any
from shared.advanced_logger import advanced_logger

class NestedEncryption:
    def __init__(self):
        self.encryption_stack = []
    
    def add_algorithm(self, algorithm: str, key: str, params: Dict[str, Any] = None):
        self.encryption_stack.append({
            "algorithm": algorithm,
            "key": key,
            "params": params or {}
        })
    
    def encrypt(self, data: Union[str, bytes], algorithms_module) -> Union[str, bytes]:
        if not self.encryption_stack:
            raise ValueError("En az bir algoritma eklenmelidir")
        
        result = data
        start_time = time.time()
        
        try:
            for i, layer in enumerate(self.encryption_stack):
                algorithm = layer["algorithm"]
                key = layer["key"]
                params = layer["params"]
                
                cipher = algorithms_module.get_algorithm(algorithm)
                
                if isinstance(result, str):
                    result = cipher.encrypt(result, **params)
                else:
                    result_str = result.decode('utf-8') if isinstance(result, bytes) else str(result)
                    result = cipher.encrypt(result_str, **params)
                
                advanced_logger.debug(
                    f"Nested encryption layer {i+1}/{len(self.encryption_stack)}: {algorithm}",
                    "NestedEncryption"
                )
            
            duration = time.time() - start_time
            advanced_logger.log_performance(
                "nested_encryption",
                duration,
                {"layers": len(self.encryption_stack)}
            )
            
            return result
        
        except Exception as e:
            advanced_logger.error(f"Nested encryption hatası: {str(e)}", "NestedEncryption")
            raise
    
    def decrypt(self, data: Union[str, bytes], algorithms_module) -> Union[str, bytes]:
        if not self.encryption_stack:
            raise ValueError("En az bir algoritma eklenmelidir")
        
        result = data
        start_time = time.time()
        
        try:
            for i, layer in enumerate(reversed(self.encryption_stack)):
                algorithm = layer["algorithm"]
                key = layer["key"]
                params = layer["params"]
                
                cipher = algorithms_module.get_algorithm(algorithm)
                
                if isinstance(result, str):
                    result = cipher.decrypt(result, **params)
                else:
                    result_str = result.decode('utf-8') if isinstance(result, bytes) else str(result)
                    result = cipher.decrypt(result_str, **params)
                
                advanced_logger.debug(
                    f"Nested decryption layer {len(self.encryption_stack)-i}/{len(self.encryption_stack)}: {algorithm}",
                    "NestedEncryption"
                )
            
            duration = time.time() - start_time
            advanced_logger.log_performance(
                "nested_decryption",
                duration,
                {"layers": len(self.encryption_stack)}
            )
            
            return result
        
        except Exception as e:
            advanced_logger.error(f"Nested decryption hatası: {str(e)}", "NestedEncryption")
            raise
    
    def clear(self):
        self.encryption_stack.clear()

