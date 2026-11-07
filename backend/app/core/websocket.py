import json
import logging
from typing import Dict, List, Set

from fastapi import WebSocket

logger = logging.getLogger("threatlens.websocket")

class ConnectionManager:
    def __init__(self):
        # channel_name -> set of WebSockets
        self.channel_subscribers: Dict[str, Set[WebSocket]] = {
            "alerts.stream": set(),
            "indicators.high_severity": set(),
            "system.health": set(),
        }
        self.all_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket, channel: str = "alerts.stream"):
        await websocket.accept()
        self.all_connections.append(websocket)
        if channel not in self.channel_subscribers:
            self.channel_subscribers[channel] = set()
        self.channel_subscribers[channel].add(websocket)
        logger.info(f"WebSocket client connected to channel: {channel}. Total active: {len(self.all_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.all_connections:
            self.all_connections.remove(websocket)
        for channel, subscribers in self.channel_subscribers.items():
            if websocket in subscribers:
                subscribers.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total active: {len(self.all_connections)}")

    async def broadcast(self, channel: str, message: dict):
        if channel in self.channel_subscribers:
            dead_sockets = []
            for websocket in self.channel_subscribers[channel]:
                try:
                    await websocket.send_text(json.dumps(message))
                except Exception as e:
                    logger.warning(f"Failed to send to websocket, marking dead: {e}")
                    dead_sockets.append(websocket)
            for dead in dead_sockets:
                self.disconnect(dead)

    async def broadcast_all(self, message: dict):
        dead_sockets = []
        for websocket in self.all_connections:
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.warning(f"Failed to send to websocket, marking dead: {e}")
                dead_sockets.append(websocket)
        for dead in dead_sockets:
            self.disconnect(dead)

ws_manager = ConnectionManager()
