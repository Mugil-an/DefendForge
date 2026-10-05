"""
WebSocket connection manager for real-time event streaming to the 3D dashboard.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List

from fastapi import WebSocket
from fastapi.encoders import jsonable_encoder
from blue_agent.logging_cfg import get_logger

log = get_logger("api.ws_manager")


class ConnectionManager:
    """Manages WebSocket connections and broadcasts events to all connected clients."""

    def __init__(self):
        self._connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self._connections.append(websocket)
        log.info("ws_client_connected", total=len(self._connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self._connections:
            self._connections.remove(websocket)
        log.info("ws_client_disconnected", total=len(self._connections))

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast a JSON message to all connected WebSocket clients."""
        data = json.dumps(jsonable_encoder(message))
        dead = []
        for ws in self._connections:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def broadcast_event(self, event_type: str, payload: Dict[str, Any]):
        """Broadcast a typed event to all clients."""
        await self.broadcast({
            "type": event_type,
            "data": payload,
        })


# Singleton
ws_manager = ConnectionManager()
