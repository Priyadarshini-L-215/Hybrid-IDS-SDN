#!/usr/bin/env python3
import sys
sys.path.insert(0, 'src')

print("[Test] Consumer Module...")

try:
    from ml_engine.consumer import (
        eve_batch_to_redis,
        redis_reader_task,
        redis_pipeline_main,
        log_tailer
    )
    print("  ✓ All consumer functions imported")
    print("    - eve_batch_to_redis (callback for batch processing)")
    print("    - redis_reader_task (async file watcher)")
    print("    - redis_pipeline_main (main Redis pipeline entry)")
    print("    - log_tailer (legacy fallback)")
    
    from common.config import USE_REDIS_QUEUE
    print(f"\n[Test] Pipeline Mode Selection...")
    if USE_REDIS_QUEUE:
        print("  → Using Redis Pipeline (use_redis_queue=True)")
        print("    Expected: async file watcher → Redis queue → worker pool → WebSocket")
    else:
        print("  → Using Legacy Polling (use_redis_queue=False)")
        print("    Expected: file polling → direct processing → WebSocket")
    
    print("\n[SUCCESS] Consumer module ready for Redis pipeline!")
    
except Exception as e:
    print(f"\n[ERROR] Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
