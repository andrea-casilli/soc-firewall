import json
import time
import threading
import asyncio
import websockets
from typing import Dict, Set, Optional, Any, Callable
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict
import queue

from src.utils.logger import get_logger

logger = get_logger(__name__)


class EventType(Enum):
    """WebSocket event types"""
    PACKET = "packet"
    ALERT = "alert"
    INCIDENT = "incident"
    QUARANTINE = "quarantine"
    CONNECTION = "connection"
    STATISTICS = "statistics"
    SYSTEM = "system"
    HEARTBEAT = "heartbeat"


@dataclass
class WebSocketMessage:
    """WebSocket message structure"""
    type: EventType
    data: Any
    timestamp: float = field(default_factory=time.time)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps({
            'type': self.type.value,
            'data': self.data,
            'timestamp': self.timestamp
        })


class WebSocketClient:
    """Represents a connected WebSocket client"""
    
    def __init__(self, websocket, client_id: str):
        """
        Initialize client
        
        Args:
            websocket: WebSocket connection
            client_id: Client ID
        """
        self.websocket = websocket
        self.client_id = client_id
        self.subscriptions: Set[EventType] = set()
        self.connected_at = time.time()
        self.last_heartbeat = time.time()
        self.message_queue = queue.Queue()
        self.running = True
    
    async def send(self, message: WebSocketMessage) -> None:
        """Send message to client"""
        try:
            await self.websocket.send(message.to_json())
        except Exception as e:
            logger.error(f"Error sending to client {self.client_id}: {e}")
    
    def subscribe(self, event_type: EventType) -> None:
        """Subscribe to event type"""
        self.subscriptions.add(event_type)
        logger.debug(f"Client {self.client_id} subscribed to {event_type.value}")
    
    def unsubscribe(self, event_type: EventType) -> None:
        """Unsubscribe from event type"""
        self.subscriptions.discard(event_type)
        logger.debug(f"Client {self.client_id} unsubscribed from {event_type.value}")
    
    def is_subscribed(self, event_type: EventType) -> bool:
        """Check if subscribed to event type"""
        return event_type in self.subscriptions
    
    def update_heartbeat(self) -> None:
        """Update last heartbeat time"""
        self.last_heartbeat = time.time()
    
    def is_alive(self, timeout: int = 30) -> bool:
        """Check if client is still alive"""
        return time.time() - self.last_heartbeat < timeout


class WebSocketServer:
    """
    WebSocket server for real-time event streaming
    
    Features:
    - Real-time event broadcasting
    - Client subscription management
    - Heartbeat monitoring
    - Event filtering per client
    - Multiple event types
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        """
        Initialize WebSocket server
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        self.host = host
        self.port = port
        self.clients: Dict[str, WebSocketClient] = {}
        self.event_handlers: Dict[EventType, List[Callable]] = defaultdict(list)
        
        # Statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "messages_sent": 0,
            "events_broadcast": 0
        }
        
        self.lock = threading.RLock()
        self.running = False
        self.server = None
    
    async def register_client(self, websocket) -> WebSocketClient:
        """
        Register a new client
        
        Args:
            websocket: WebSocket connection
            
        Returns:
            Client object
        """
        client_id = f"client_{int(time.time())}_{len(self.clients)}"
        
        with self.lock:
            client = WebSocketClient(websocket, client_id)
            self.clients[client_id] = client
            self.stats["total_connections"] += 1
            self.stats["active_connections"] = len(self.clients)
        
        logger.info(f"Client registered: {client_id}")
        return client
    
    async def unregister_client(self, client_id: str) -> None:
        """
        Unregister a client
        
        Args:
            client_id: Client ID
        """
        with self.lock:
            if client_id in self.clients:
                del self.clients[client_id]
                self.stats["active_connections"] = len(self.clients)
        
        logger.info(f"Client unregistered: {client_id}")
    
    async def handle_client(self, websocket, path: str) -> None:
        """
        Handle client connection
        
        Args:
            websocket: WebSocket connection
            path: Connection path
        """
        client = await self.register_client(websocket)
        
        try:
            # Send welcome message
            await client.send(WebSocketMessage(
                type=EventType.SYSTEM,
                data={
                    'message': 'Connected to SOC Firewall WebSocket',
                    'client_id': client.client_id,
                    'timestamp': time.time()
                }
            ))
            
            # Handle messages
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self.handle_message(client, data)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON from client {client.client_id}")
                except Exception as e:
                    logger.error(f"Error handling message from {client.client_id}: {e}")
        
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client disconnected: {client.client_id}")
        finally:
            await self.unregister_client(client.client_id)
    
    async def handle_message(self, client: WebSocketClient, data: Dict) -> None:
        """
        Handle client message
        
        Args:
            client: Client object
            data: Message data
        """
        message_type = data.get('type')
        
        if message_type == 'subscribe':
            event_types = data.get('events', [])
            for event_type_str in event_types:
                try:
                    event_type = EventType(event_type_str)
                    client.subscribe(event_type)
                except ValueError:
                    logger.warning(f"Invalid event type: {event_type_str}")
            
            await client.send(WebSocketMessage(
                type=EventType.SYSTEM,
                data={'message': f'Subscribed to: {event_types}'}
            ))
        
        elif message_type == 'unsubscribe':
            event_types = data.get('events', [])
            for event_type_str in event_types:
                try:
                    event_type = EventType(event_type_str)
                    client.unsubscribe(event_type)
                except ValueError:
                    pass
        
        elif message_type == 'heartbeat':
            client.update_heartbeat()
            await client.send(WebSocketMessage(
                type=EventType.HEARTBEAT,
                data={'status': 'ok'}
            ))
        
        elif message_type == 'ping':
            await client.send(WebSocketMessage(
                type=EventType.SYSTEM,
                data={'message': 'pong'}
            ))
        
        elif message_type == 'get_status':
            await client.send(WebSocketMessage(
                type=EventType.SYSTEM,
                data={
                    'status': 'running',
                    'clients': len(self.clients),
                    'subscriptions': [e.value for e in client.subscriptions]
                }
            ))
    
    async def broadcast(self, message: WebSocketMessage, event_type: Optional[EventType] = None) -> int:
        """
        Broadcast message to all subscribed clients
        
        Args:
            message: Message to broadcast
            event_type: Event type (for filtering)
            
        Returns:
            Number of clients message was sent to
        """
        sent_count = 0
        
        with self.lock:
            clients = list(self.clients.values())
        
        for client in clients:
            if event_type is None or client.is_subscribed(event_type):
                try:
                    await client.send(message)
                    sent_count += 1
                except Exception as e:
                    logger.error(f"Error broadcasting to {client.client_id}: {e}")
        
        with self.lock:
            self.stats["messages_sent"] += sent_count
            if event_type:
                self.stats["events_broadcast"] += 1
        
        return sent_count
    
    async def broadcast_alert(self, alert_data: Dict) -> int:
        """Broadcast alert event"""
        return await self.broadcast(
            WebSocketMessage(type=EventType.ALERT, data=alert_data),
            event_type=EventType.ALERT
        )
    
    async def broadcast_incident(self, incident_data: Dict) -> int:
        """Broadcast incident event"""
        return await self.broadcast(
            WebSocketMessage(type=EventType.INCIDENT, data=incident_data),
            event_type=EventType.INCIDENT
        )
    
    async def broadcast_packet(self, packet_data: Dict) -> int:
        """Broadcast packet event"""
        return await self.broadcast(
            WebSocketMessage(type=EventType.PACKET, data=packet_data),
            event_type=EventType.PACKET
        )
    
    async def broadcast_quarantine(self, quarantine_data: Dict) -> int:
        """Broadcast quarantine event"""
        return await self.broadcast(
            WebSocketMessage(type=EventType.QUARANTINE, data=quarantine_data),
            event_type=EventType.QUARANTINE
        )
    
    async def broadcast_statistics(self, stats_data: Dict) -> int:
        """Broadcast statistics event"""
        return await self.broadcast(
            WebSocketMessage(type=EventType.STATISTICS, data=stats_data),
            event_type=EventType.STATISTICS
        )
    
    def register_event_handler(self, event_type: EventType, handler: Callable) -> None:
        """
        Register event handler
        
        Args:
            event_type: Event type
            handler: Handler function
        """
        with self.lock:
            self.event_handlers[event_type].append(handler)
    
    async def start(self) -> None:
        """Start WebSocket server"""
        self.running = True
        
        # Start heartbeat monitor
        asyncio.create_task(self._heartbeat_monitor())
        
        # Start server
        async with websockets.serve(self.handle_client, self.host, self.port):
            logger.info(f"WebSocket server started on ws://{self.host}:{self.port}")
            await asyncio.Future()  # Run forever
    
    def run(self) -> None:
        """Run WebSocket server in event loop"""
        asyncio.run(self.start())
    
    async def _heartbeat_monitor(self) -> None:
        """Monitor client heartbeats"""
        while self.running:
            await asyncio.sleep(30)  # Check every 30 seconds
            
            with self.lock:
                clients = list(self.clients.items())
            
            for client_id, client in clients:
                if not client.is_alive():
                    logger.warning(f"Client {client_id} timed out, closing connection")
                    try:
                        await client.websocket.close()
                    except:
                        pass
                    await self.unregister_client(client_id)
    
    def stop(self) -> None:
        """Stop WebSocket server"""
        self.running = False
        logger.info("WebSocket server stopped")
    
    def get_statistics(self) -> Dict:
        """Get server statistics"""
        with self.lock:
            return {
                "total_connections": self.stats["total_connections"],
                "active_connections": self.stats["active_connections"],
                "messages_sent": self.stats["messages_sent"],
                "events_broadcast": self.stats["events_broadcast"],
                "clients": [
                    {
                        "id": c.client_id,
                        "connected_at": c.connected_at,
                        "subscriptions": [e.value for e in c.subscriptions],
                        "last_heartbeat": c.last_heartbeat
                    }
                    for c in self.clients.values()
                ]
            }


# Synchronous wrapper for broadcasting from non-async code
class WebSocketBroadcaster:
    """
    Synchronous wrapper for WebSocket broadcasting
    Allows broadcasting from non-async code
    """
    
    def __init__(self, server: WebSocketServer):
        """
        Initialize broadcaster
        
        Args:
            server: WebSocket server instance
        """
        self.server = server
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
    
    def _run_loop(self) -> None:
        """Run asyncio loop in thread"""
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()
    
    def broadcast_alert(self, alert_data: Dict) -> None:
        """Broadcast alert"""
        asyncio.run_coroutine_threadsafe(
            self.server.broadcast_alert(alert_data),
            self.loop
        )
    
    def broadcast_incident(self, incident_data: Dict) -> None:
        """Broadcast incident"""
        asyncio.run_coroutine_threadsafe(
            self.server.broadcast_incident(incident_data),
            self.loop
        )
    
    def broadcast_packet(self, packet_data: Dict) -> None:
        """Broadcast packet"""
        asyncio.run_coroutine_threadsafe(
            self.server.broadcast_packet(packet_data),
            self.loop
        )
    
    def broadcast_statistics(self, stats_data: Dict) -> None:
        """Broadcast statistics"""
        asyncio.run_coroutine_threadsafe(
            self.server.broadcast_statistics(stats_data),
            self.loop
        )
    
    def stop(self) -> None:
        """Stop broadcaster"""
        self.loop.call_soon_threadsafe(self.loop.stop)
