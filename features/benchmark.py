import time
import statistics
from typing import List, Dict, Any
from shared.advanced_logger import advanced_logger

class EncryptionBenchmark:
    def __init__(self):
        self.results = {}
    
    def benchmark_algorithm(self, algorithm_name: str, encrypt_func: callable, 
                          decrypt_func: callable, test_data: str, 
                          iterations: int = 10) -> Dict[str, Any]:
        encrypt_times = []
        decrypt_times = []
        success_count = 0
        
        for i in range(iterations):
            try:
                start = time.time()
                encrypted = encrypt_func(test_data)
                encrypt_time = time.time() - start
                encrypt_times.append(encrypt_time)
                
                start = time.time()
                decrypted = decrypt_func(encrypted)
                decrypt_time = time.time() - start
                decrypt_times.append(decrypt_time)
                
                if decrypted == test_data:
                    success_count += 1
            except Exception as e:
                advanced_logger.error(f"Benchmark iterasyon {i+1} hatası: {str(e)}", "Benchmark")
        
        result = {
            "algorithm": algorithm_name,
            "iterations": iterations,
            "success_rate": (success_count / iterations) * 100,
            "encrypt": {
                "mean": statistics.mean(encrypt_times) if encrypt_times else 0,
                "median": statistics.median(encrypt_times) if encrypt_times else 0,
                "min": min(encrypt_times) if encrypt_times else 0,
                "max": max(encrypt_times) if encrypt_times else 0,
                "std_dev": statistics.stdev(encrypt_times) if len(encrypt_times) > 1 else 0
            },
            "decrypt": {
                "mean": statistics.mean(decrypt_times) if decrypt_times else 0,
                "median": statistics.median(decrypt_times) if decrypt_times else 0,
                "min": min(decrypt_times) if decrypt_times else 0,
                "max": max(decrypt_times) if decrypt_times else 0,
                "std_dev": statistics.stdev(decrypt_times) if len(decrypt_times) > 1 else 0
            },
            "data_size": len(test_data)
        }
        
        self.results[algorithm_name] = result
        
        advanced_logger.log_performance(
            f"benchmark_{algorithm_name}",
            result["encrypt"]["mean"] + result["decrypt"]["mean"],
            result
        )
        
        return result
    
    def compare_algorithms(self, algorithms: List[Dict[str, Any]]) -> Dict[str, Any]:
        comparison = {
            "algorithms": [],
            "fastest_encrypt": None,
            "fastest_decrypt": None,
            "most_reliable": None
        }
        
        fastest_encrypt_time = float('inf')
        fastest_decrypt_time = float('inf')
        highest_success_rate = 0
        
        for algo_result in algorithms:
            comparison["algorithms"].append(algo_result)
            
            if algo_result["encrypt"]["mean"] < fastest_encrypt_time:
                fastest_encrypt_time = algo_result["encrypt"]["mean"]
                comparison["fastest_encrypt"] = algo_result["algorithm"]
            
            if algo_result["decrypt"]["mean"] < fastest_decrypt_time:
                fastest_decrypt_time = algo_result["decrypt"]["mean"]
                comparison["fastest_decrypt"] = algo_result["algorithm"]
            
            if algo_result["success_rate"] > highest_success_rate:
                highest_success_rate = algo_result["success_rate"]
                comparison["most_reliable"] = algo_result["algorithm"]
        
        return comparison
    
    def get_results(self) -> Dict[str, Any]:
        return self.results.copy()
    
    def clear_results(self):
        self.results.clear()

