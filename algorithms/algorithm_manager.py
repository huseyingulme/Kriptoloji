"""
Algoritma yöneticisi
Tüm şifreleme algoritmalarını yönetir
"""

from typing import Dict, List, Any, Optional
from . import get_algorithm, get_available_algorithms, get_algorithm_info


class AlgorithmManager:
    """
    Şifreleme algoritmalarını yöneten sınıf
    """
    
    def __init__(self):
        """Algoritma yöneticisini başlatır"""
        self.available_algorithms = get_available_algorithms()
    
    def get_algorithm(self, name: str):
        """
        Algoritma adına göre algoritma sınıfını döndürür
        
        Args:
            name: Algoritma adı
            
        Returns:
            Algoritma sınıfı
        """
        return get_algorithm(name)
    
    def get_available_algorithms(self) -> List[str]:
        """
        Mevcut algoritmaları döndürür
        
        Returns:
            Algoritma adları listesi
        """
        return self.available_algorithms.copy()
    
    def get_algorithm_info(self, name: str) -> Dict[str, Any]:
        """
        Algoritma hakkında bilgi döndürür
        
        Args:
            name: Algoritma adı
            
        Returns:
            Algoritma bilgileri
        """
        return get_algorithm_info(name)
    
    def validate_algorithm(self, name: str) -> bool:
        """
        Algoritmanın mevcut olup olmadığını kontrol eder
        
        Args:
            name: Algoritma adı
            
        Returns:
            Algoritma mevcutsa True
        """
        return name in self.available_algorithms
    
    def get_algorithm_requirements(self, name: str) -> List[str]:
        """
        Algoritmanın gerektirdiği parametreleri döndürür
        
        Args:
            name: Algoritma adı
            
        Returns:
            Gerekli parametreler listesi
        """
        try:
            algorithm = self.get_algorithm(name)
            return algorithm.required_params.copy()
        except Exception:
            return []
    
    def get_all_algorithms_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Tüm algoritmalar hakkında bilgi döndürür
        
        Returns:
            Algoritma bilgileri sözlüğü
        """
        algorithms_info = {}
        for algorithm_name in self.available_algorithms:
            try:
                algorithms_info[algorithm_name] = self.get_algorithm_info(algorithm_name)
            except Exception:
                algorithms_info[algorithm_name] = {
                    'name': algorithm_name,
                    'error': 'Bilgi alınamadı'
                }
        return algorithms_info


# Global algoritma yöneticisi instance'ı
algorithm_manager = AlgorithmManager()
