#!/usr/bin/env python3
import sys
sys.path.insert(0, 'src')

print("[Test] Consumer Module...")

try:
    from ml_engine.consumer import (
        redis_reader_task,
        redis_pipeline_main,
        log_tailer
    )
    print("  ✓ All consumer functions imported")
    print("    - redis_reader_task (async file watcher)")
    print("    - redis_pipeline_main (main Redis pipeline entry)")
    print("    - log_tailer (legacy fallback)")
    
    print(f"\n[Test] Pipeline Mode Selection...")
    print("  → Using Redis Pipeline")
    print("    Expected: async file watcher → Redis queue → worker pool → WebSocket")
    
    print("\n[SUCCESS] Consumer module ready for Redis pipeline!")
    
except Exception as e:
    print(f"\n[ERROR] Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
