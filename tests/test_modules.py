#!/usr/bin/env python3
import sys
sys.path.insert(0, 'src')

print("[Test] Module Imports...")

try:
    print("  Loading redis_client...")
    from ml_engine.redis_client import test_redis, get_redis_info
    print("    ✓ redis_client")
    
    print("  Loading file_watcher...")
    from ml_engine.file_watcher import AsyncFileWatcher
    print("    ✓ file_watcher")
    
    print("  Loading worker_pool...")
    from ml_engine.worker_pool import WorkerPool
    print("    ✓ worker_pool")
    
    print("  Loading config...")
    from common.config import (
        REDIS_HOST, REDIS_PORT, REDIS_QUEUE_NAME, 
        USE_REDIS_QUEUE, WORKER_COUNT, BATCH_SIZE
    )
    print(f"    ✓ config (Redis: {REDIS_HOST}:{REDIS_PORT}, Workers: {WORKER_COUNT})")
    
    print("\n[Test] Redis Feature Flag Status...")
    print(f"  USE_REDIS_QUEUE: {USE_REDIS_QUEUE}")
    print(f"  WORKER_COUNT: {WORKER_COUNT}")
    print(f"  BATCH_SIZE: {BATCH_SIZE}")
    
    print("\n[SUCCESS] All modules loaded successfully!")
    
except Exception as e:
    print(f"\n[ERROR] Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
