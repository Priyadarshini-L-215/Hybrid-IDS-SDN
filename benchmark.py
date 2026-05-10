import asyncio
import time
import sys
import os

# Add src to PYTHONPATH
sys.path.insert(0, os.path.abspath("src"))

from ml_engine.sdn_client import SDNClient

async def benchmark_unblock(client, n=100):
    start = time.time()
    tasks = [client.unblock("1.1.1.1") for _ in range(n)]
    await asyncio.gather(*tasks)
    return time.time() - start

async def main():
    client = SDNClient("http://127.0.0.1:8080")

    # Warm up
    await benchmark_unblock(client, 10)

    # Run
    n = 200
    duration = await benchmark_unblock(client, n)
    print(f"Time for {n} requests: {duration:.4f}s")
    print(f"Requests per second: {n/duration:.2f}")

if __name__ == "__main__":
    asyncio.run(main())
