from token_tango.key_rotation_event import KeyRotationEvent
from token_tango.singleton_meta import SingletonMeta


class KeyManager(metaclass=SingletonMeta):
    _public_keys: dict[str, KeyRotationEvent] = {}

    def add_key(self, key_rotation_event: KeyRotationEvent) -> None:
        self._public_keys[key_rotation_event.key_id] = key_rotation_event

    def get_key_by_id(self, key_id: str) -> KeyRotationEvent | None:
        return self._public_keys.get(key_id)
