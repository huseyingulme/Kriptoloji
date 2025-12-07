from typing import List, Dict, Any, Callable, Optional
from shared.performance import get_task_queue
from shared.advanced_logger import advanced_logger
import time

class BatchProcessor:
    def __init__(self):
        self.queue = get_task_queue()
        self.results = []
    
    def process_batch(self, items: List[Dict[str, Any]], 
                     process_func: Callable,
                     progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        task_ids = []
        total = len(items)
        
        start_time = time.time()
        
        for i, item in enumerate(items):
            task_id = self.queue.submit(process_func, item)
            task_ids.append((task_id, item, i))
            
            if progress_callback:
                progress_callback((i + 1) / total * 100)
        
        results = []
        for task_id, item, index in task_ids:
            result = self.queue.get_result(task_id, timeout=300)
            if result:
                results.append({
                    "index": index,
                    "item": item,
                    "success": result.get("success", False),
                    "data": result.get("result"),
                    "error": result.get("error"),
                    "duration": result.get("duration", 0)
                })
            else:
                results.append({
                    "index": index,
                    "item": item,
                    "success": False,
                    "error": "Timeout",
                    "duration": 0
                })
            
            if progress_callback:
                progress_callback((len(results) / total) * 100)
        
        duration = time.time() - start_time
        success_count = sum(1 for r in results if r["success"])
        
        advanced_logger.log_performance(
            "batch_processing",
            duration,
            {
                "total": total,
                "success": success_count,
                "failed": total - success_count
            }
        )
        
        advanced_logger.log_operation(
            "batch_process",
            "multiple",
            success_count == total,
            {
                "total": total,
                "success": success_count,
                "failed": total - success_count
            }
        )
        
        return results
    
    def encrypt_batch(self, items: List[Dict[str, Any]], 
                     encrypt_func: Callable,
                     progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        def process_item(item):
            try:
                result = encrypt_func(
                    item.get("data"),
                    item.get("algorithm"),
                    **item.get("params", {})
                )
                return {"success": True, "result": result}
            except Exception as e:
                return {"success": False, "error": str(e)}
        
        return self.process_batch(items, process_item, progress_callback)
    
    def decrypt_batch(self, items: List[Dict[str, Any]], 
                     decrypt_func: Callable,
                     progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        def process_item(item):
            try:
                result = decrypt_func(
                    item.get("data"),
                    item.get("algorithm"),
                    **item.get("params", {})
                )
                return {"success": True, "result": result}
            except Exception as e:
                return {"success": False, "error": str(e)}
        
        return self.process_batch(items, process_item, progress_callback)

