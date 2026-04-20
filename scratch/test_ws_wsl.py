import asyncio
import websockets
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ws_test")

async def handler(websocket, path):
    logger.info("Client connected")
    await websocket.wait_closed()

async def main():
    logger.info("Starting server on 0.0.0.0:8765")
    async with websockets.serve(handler, "0.0.0.0", 8765):
        logger.info("Server started. Press Ctrl+C to stop.")
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
