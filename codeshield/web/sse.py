"""
CodeShield SSE — Server-Sent Events for Real-Time Progress

Thread-safe event bus for pushing live scan progress to the web UI.
"""

import time
import json
import queue
import threading
import logging
from typing import Dict, Generator, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger("codeshield.web.sse")


@dataclass
class ScanEvent:
    """A single scan progress event."""
    scan_id: str
    plugin_name: str
    status: str          # queued, running, complete, failed, extracting, analyzing
    detail: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


class EventBus:
    """
    Thread-safe event bus for SSE.
    Multiple listeners can subscribe to events for a specific scan.
    """

    def __init__(self):
        self._listeners: Dict[str, list] = {}
        self._lock = threading.Lock()
        # Buffer recent events per scan for late-joining listeners
        self._event_buffer: Dict[str, list] = {}
        self._buffer_limit = 100

    def publish(self, event: ScanEvent) -> None:
        """Publish an event to all listeners for the given scan."""
        scan_id = event.scan_id

        with self._lock:
            # Buffer the event
            if scan_id not in self._event_buffer:
                self._event_buffer[scan_id] = []
            buffer = self._event_buffer[scan_id]
            buffer.append(event)
            if len(buffer) > self._buffer_limit:
                buffer.pop(0)

            # Push to all active listeners
            listeners = self._listeners.get(scan_id, [])
            for q in listeners:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    pass  # Drop event if listener is behind

    def subscribe(self, scan_id: str) -> Generator[str, None, None]:
        """
        Subscribe to events for a scan. Returns a generator that yields
        SSE-formatted event strings. Includes buffered past events.
        """
        q: queue.Queue = queue.Queue(maxsize=200)

        with self._lock:
            if scan_id not in self._listeners:
                self._listeners[scan_id] = []
            self._listeners[scan_id].append(q)

            # Replay buffered events
            for event in self._event_buffer.get(scan_id, []):
                try:
                    q.put_nowait(event)
                except queue.Full:
                    break

        try:
            while True:
                try:
                    event = q.get(timeout=30.0)
                    data = json.dumps(asdict(event))
                    yield f"data: {data}\n\n"

                    # End stream on terminal events
                    if (event.plugin_name == "engine" and
                            event.status in ("complete", "failed")):
                        break
                except queue.Empty:
                    # Send keepalive to prevent connection timeout
                    yield ": keepalive\n\n"
        finally:
            with self._lock:
                listeners = self._listeners.get(scan_id, [])
                if q in listeners:
                    listeners.remove(q)

    def cleanup_scan(self, scan_id: str) -> None:
        """Remove event buffer for a completed scan."""
        with self._lock:
            self._event_buffer.pop(scan_id, None)
            self._listeners.pop(scan_id, None)


# Module-level singleton
event_bus = EventBus()
