from __future__ import annotations

import os
from typing import Optional

from pymongo import MongoClient

from id_sast_csharp.infrastructure.config.settings import Settings


class MongoDbClient:
    def __init__(self, uri: Optional[str] = None, db_name: Optional[str] = None):
        self.uri = uri or os.getenv("MONGODB_URI", Settings.MONGODB_URI)
        self.db_name = db_name or os.getenv("MONGODB_DB_NAME", Settings.MONGODB_DB_NAME)
        self.client: Optional[MongoClient] = None
        self.db = None

    def connect(self) -> bool:
        if not self.uri:
            return False
        self.client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
        self.db = self.client[self.db_name]
        try:
            self.client.admin.command("ping")
            return True
        except Exception:
            self.disconnect()
            return False

    def disconnect(self) -> None:
        if self.client:
            self.client.close()
        self.client = None
        self.db = None

