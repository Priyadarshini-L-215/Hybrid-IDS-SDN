import asyncio
import os
import signal
import yaml
import json
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import Response
import structlog
import aiofiles
import hashlib

from common.config import CONFIG_PATH
from pydantic import BaseModel, Field, ValidationError
from common.config_schema import SentinelConfig
from relay.middleware.auth import require_api_key

logger = structlog.get_logger("relay.routes.config")
router = APIRouter(prefix="/api", tags=["Configuration"])

class ConfigUpdate(BaseModel):
    config: dict = Field(..., description="Full configuration object")

@router.get("/config")
async def get_config(request: Request):
    """Returns the current sentinel_config.yaml content with ETag caching."""
    try:
        if CONFIG_PATH.exists():
            async with aiofiles.open(CONFIG_PATH, "r") as f:
                content = await f.read()
                etag = f'W/"{hashlib.md5(content.encode()).hexdigest()}"'
                
                if request.headers.get("if-none-match") == etag:
                    return Response(status_code=304)
                
                loop = asyncio.get_running_loop()
                data = await loop.run_in_executor(None, yaml.safe_load, content) or {}

                return Response(
                    content=json.dumps(data),
                    media_type="application/json",
                    headers={"ETag": etag, "Cache-Control": "public, max-age=30"}
                )
        return {}
    except Exception as e:
        logger.error("Failed to read config", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to read configuration file")

@router.post("/config", dependencies=[Depends(require_api_key)])
async def update_config(req: ConfigUpdate):
    """Updates and saves the sentinel_config.yaml file and reloads in all services.
    
    The incoming config dict is validated against the full SentinelConfig Pydantic schema
    before any write occurs. Returns 422 if the payload violates the schema.
    """
    try:
        validated = SentinelConfig(**req.config)
        new_config = validated.model_dump(exclude_none=True)
    except ValidationError as exc:
        # Use exc.json() then loads to ensure all objects (like ValueErrors in ctx) are serialized
        raise HTTPException(status_code=422, detail=json.loads(exc.json()))

    try:
        def dump_yaml():
            with open(CONFIG_PATH, "w") as f:
                yaml.dump(new_config, f, default_flow_style=False)

        await asyncio.to_thread(dump_yaml)
        logger.info("Configuration updated successfully")
        
        try:
            from common.config import refresh_config
            refresh_config()
            logger.info("Config refreshed in relay service")
        except Exception as e:
            logger.warning("Failed to refresh config locally", error=str(e))
        
        try:
            import psutil
            current_user = psutil.Process().username()
            signaled_count = 0
            for proc in psutil.process_iter(["pid", "cmdline", "username"]):
                try:
                    cmdline = " ".join(proc.info.get("cmdline") or [])
                    if "consumer.py" in cmdline and proc.info.get("username") == current_user:
                        os.kill(proc.info["pid"], signal.SIGHUP)
                        signaled_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError, PermissionError):
                    continue
            if signaled_count == 0:
                logger.warning("No consumer processes found to signal")
        except Exception as e:
            logger.warning("Failed to signal consumer for reload", error=str(e))
            
        return {"success": True, "message": "Config updated and reload signal sent"}
    except Exception as e:
        logger.error("Failed to update config", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to save configuration")
