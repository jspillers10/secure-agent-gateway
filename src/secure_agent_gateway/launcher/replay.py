"""Process-local atomic replay guard for one-use execution grants."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class GrantReplayGuard:
    _claimed: set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def claim(self, nonce: str) -> bool:
        with self._lock:
            if nonce in self._claimed:
                return False
            self._claimed.add(nonce)
            return True
