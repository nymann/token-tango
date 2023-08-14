from collections.abc import Iterable
import logging
from typing import Optional

from confluent_kafka import Consumer
from confluent_kafka import KafkaError

from token_tango.config import KafkaConfig
from token_tango.key_rotation_event import KeyRotationEvent


class KeyRotationConsumer:
    def __init__(self, config: KafkaConfig) -> None:
        self.consumer = Consumer(config.consumer_options)
        self.consumer.subscribe([config.topic])
        self._should_consume = True

    def consume(self) -> Iterable[KeyRotationEvent]:
        try:
            while self._should_consume:
                yield from self._consume_messages()
        except KeyboardInterrupt:
            logging.info("Consumer was interrupted by user")

    def _consume_messages(self) -> Iterable[KeyRotationEvent]:
        for message in self.consumer.consume(timeout=10):
            logging.debug("Received new Key Rotation Event")
            error: Optional[KafkaError] = message.error()
            if error:
                logging.error(error)
                continue
            yield KeyRotationEvent.from_json(message.value().decode())

    def close(self) -> None:
        self._should_consume = False
        self.consumer.close()
