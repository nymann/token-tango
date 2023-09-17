from threading import Lock
from typing import Any, Generic, TypeVar

T = TypeVar("T")  # noqa: WPS111


class SingletonMeta(type, Generic[T]):
    _instances: dict[type[T], T] = {}
    _lock: Lock = Lock()

    def __call__(cls: "SingletonMeta", *args: Any, **kwargs: Any) -> T:
        with cls._lock:
            if cls not in cls._instances:
                instance = super().__call__(*args, **kwargs)
                cls._instances[cls] = instance
        return cls._instances[cls]
