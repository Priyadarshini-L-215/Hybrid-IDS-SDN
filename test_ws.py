import asyncio, websockets
async def t():
    async with websockets.connect('ws://127.0.0.1:8765') as ws:
        msg = await asyncio.wait_for(ws.recv(), timeout=15)
        print('RECEIVED:', msg[:120])
asyncio.run(t())
