import threading
import queue
import time
from typing import Callable, Any, Optional, Dict
from functools import lru_cache
from shared.advanced_logger import advanced_logger

class CacheManager:
    def __init__(self, max_size_mb: int = 50):
        self.cache = {}
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.current_size = 0
        self.lock = threading.Lock()
        self.access_times = {}
    
    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key in self.cache:
                self.access_times[key] = time.time()
                return self.cache[key]
            return None
    
    def set(self, key: str, value: Any, size_bytes: int = 0):
        with self.lock:
            if size_bytes == 0:
                try:
                    size_bytes = len(str(value).encode('utf-8'))
                except:
                    size_bytes = 1024
            
            if key in self.cache:
                old_size = self._estimate_size(self.cache[key])
                self.current_size -= old_size
            
            while self.current_size + size_bytes > self.max_size_bytes and self.cache:
                self._evict_lru()
            
            self.cache[key] = value
            self.current_size += size_bytes
            self.access_times[key] = time.time()
    
    def _estimate_size(self, value: Any) -> int:
        try:
            return len(str(value).encode('utf-8'))
        except:
            return 1024
    
    def _evict_lru(self):
        if not self.access_times:
            if self.cache:
                key = next(iter(self.cache))
                del self.cache[key]
                self.current_size = 0
            return
        
        lru_key = min(self.access_times.items(), key=lambda x: x[1])[0]
        if lru_key in self.cache:
            size = self._estimate_size(self.cache[lru_key])
            del self.cache[lru_key]
            del self.access_times[lru_key]
            self.current_size -= size
    
    def clear(self):
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
            self.current_size = 0
    
    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "items": len(self.cache),
                "size_mb": round(self.current_size / (1024 * 1024), 2),
                "max_size_mb": round(self.max_size_bytes / (1024 * 1024), 2),
                "usage_percent": round((self.current_size / self.max_size_bytes) * 100, 2)
            }

class TaskQueue:
    def __init__(self, max_workers: int = 4):
        self.queue = queue.Queue()
        self.workers = []
        self.max_workers = max_workers
        self.running = False
        self.results = {}
        self.result_lock = threading.Lock()
    
    def start(self):
        if self.running:
            return
        
        self.running = True
        for i in range(self.max_workers):
            worker = threading.Thread(target=self._worker, daemon=True)
            worker.start()
            self.workers.append(worker)
    
    def stop(self):
        self.running = False
        for _ in self.workers:
            self.queue.put(None)
        for worker in self.workers:
            worker.join(timeout=5)
        self.workers.clear()
    
    def _worker(self):
        while self.running:
            try:
                task = self.queue.get(timeout=1)
                if task is None:
                    break
                
                task_id, func, args, kwargs = task
                try:
                    start_time = time.time()
                    result = func(*args, **kwargs)
                    duration = time.time() - start_time
                    
                    with self.result_lock:
                        self.results[task_id] = {
                            "success": True,
                            "result": result,
                            "duration": duration
                        }
                    
                    advanced_logger.log_performance(f"task_{task_id}", duration)
                except Exception as e:
                    with self.result_lock:
                        self.results[task_id] = {
                            "success": False,
                            "error": str(e)
                        }
                    advanced_logger.error(f"Task {task_id} hatası: {str(e)}", "TaskQueue")
                
                self.queue.task_done()
            except queue.Empty:
                continue
    
    def submit(self, func: Callable, *args, **kwargs) -> str:
        import uuid
        task_id = str(uuid.uuid4())
        self.queue.put((task_id, func, args, kwargs))
        return task_id
    
    def get_result(self, task_id: str, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        start_time = time.time()
        while True:
            with self.result_lock:
                if task_id in self.results:
                    result = self.results.pop(task_id)
                    return result
            
            if timeout and (time.time() - start_time) > timeout:
                return None
            
            time.sleep(0.1)

class StreamingProcessor:
    @staticmethod
    def process_file_stream(file_path: str, chunk_size: int = 8192, 
                           processor: Callable = None) -> bytes:
        result = b""
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    if processor:
                        chunk = processor(chunk)
                    
                    result += chunk
        except Exception as e:
            advanced_logger.error(f"Stream işleme hatası: {str(e)}", "StreamingProcessor")
            raise
        
        return result
    
    @staticmethod
    def encrypt_stream(data_stream, encrypt_func: Callable, chunk_size: int = 8192):
        while True:
            chunk = data_stream.read(chunk_size)
            if not chunk:
                break
            yield encrypt_func(chunk)
    
    @staticmethod
    def decrypt_stream(data_stream, decrypt_func: Callable, chunk_size: int = 8192):
        while True:
            chunk = data_stream.read(chunk_size)
            if not chunk:
                break
            yield decrypt_func(chunk)

def get_cache_manager() -> CacheManager:
    try:
        from config import config_manager
        max_size = config_manager.get("performance.cache_size_mb", 50)
    except:
        max_size = 50
    
    if not hasattr(get_cache_manager, '_instance'):
        get_cache_manager._instance = CacheManager(max_size)
    return get_cache_manager._instance

def get_task_queue() -> TaskQueue:
    try:
        from config import config_manager
        max_workers = config_manager.get("performance.parallel_workers", 4)
    except:
        max_workers = 4
    
    if not hasattr(get_task_queue, '_instance'):
        queue_instance = TaskQueue(max_workers)
        queue_instance.start()
        get_task_queue._instance = queue_instance
    return get_task_queue._instance

