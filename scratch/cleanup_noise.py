import sqlite3
import os

db_path = os.path.expanduser('~/.fyp_ids/alerts.db')
if not os.path.exists(db_path):
    print(f"DB not found at {db_path}")
    exit(0)

conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Noise definition:
# 1. Ports used by Sentinel control plane
# 2. Loopback traffic
# 3. Specific flows between host bridge and WSL identified by user
query = """
DELETE FROM alerts 
WHERE src_port IN (3000, 5000, 5001, 6379, 8765) 
   OR dest_port IN (3000, 5000, 5001, 6379, 8765) 
   OR src_ip IN ('127.0.0.1', '::1', '172.25.16.1') 
   OR dest_ip IN ('127.0.0.1', '::1', '172.25.16.1')
"""

cur.execute(query)
deleted = cur.rowcount
conn.commit()
conn.close()

print(f"Successfully deleted {deleted} noise alerts from database.")
