from typing import Dict, List, Any, Optional
from . import get_algorithm, get_available_algorithms, get_algorithm_info


class AlgorithmManager:
    def __init__(self):
        self.available_algorithms = get_available_algorithms()
    
    def get_algorithm(self, name: str):
        return get_algorithm(name)
    
    def get_available_algorithms(self) -> List[str]:
        return self.available_algorithms.copy()
    
    def get_algorithm_info(self, name: str) -> Dict[str, Any]:
        return get_algorithm_info(name)
    
    def validate_algorithm(self, name: str) -> bool:
        return name in self.available_algorithms
    
    def get_algorithm_requirements(self, name: str) -> List[str]:
        try:
            algorithm = self.get_algorithm(name)
            return algorithm.required_params.copy()
        except Exception:
            return []
    
    def get_all_algorithms_info(self) -> Dict[str, Dict[str, Any]]:
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


algorithm_manager = AlgorithmManager()
