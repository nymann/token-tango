from __future__ import annotations

from datetime import datetime
import json


class KeyRotationEvent:
    def __init__(
        self,
        key_id: str,
        public_key: str,
        generation_date: datetime,
        expiration_date: datetime,
    ):
        self.key_id = key_id
        self.public_key = public_key
        self.generation_date = generation_date
        self.expiration_date = expiration_date

    @classmethod
    def from_json(cls, json_str: str) -> KeyRotationEvent:
        data = json.loads(json_str)
        return cls(
            key_id=data["key_id"],
            public_key=data["public_key"],
            generation_date=datetime.fromisoformat(data["generation_date"]),
            expiration_date=datetime.fromisoformat(data["expiration_date"]),
        )
