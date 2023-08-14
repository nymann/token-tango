class KafkaConfig:
    def __init__(self, topic: str, port: int, host: str, group_id: str, **confluent_kafka_options: str | int) -> None:
        self.topic = topic
        self.consumer_options: dict[str, str | int] = {
            "bootstrap.servers": f"{host}:{port}",
            "group.id": group_id,
            "max.poll.interval.ms": 86400000,
        }
        self.consumer_options.update(**confluent_kafka_options)
