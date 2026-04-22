#!/usr/bin/env python3
import sys
sys.path.insert(0, 'src')

from ml_engine.redis_client import test_redis, get_redis_info, get_queue_depth
from common.config import REDIS_QUEUE_NAME

print("[Test] Redis Connection...")
if test_redis():
    print("[SUCCESS] Redis connection OK")
    info = get_redis_info()
    print(f"  Version: {info.get('version')}")
    print(f"  Memory: {info.get('used_memory_mb'):.1f} MB")
    print(f"  Connected clients: {info.get('connected_clients')}")
    
    print(f"\n[Test] Queue Operations ({REDIS_QUEUE_NAME})...")
    depth = get_queue_depth(REDIS_QUEUE_NAME)
    print(f"  Queue depth: {depth}")
    
    print("\n[SUCCESS] All tests passed!")
else:
    print("[ERROR] Redis connection failed")
    sys.exit(1)
