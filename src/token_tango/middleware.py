import base64
import json
from threading import Thread
from typing import Any

from fastapi import FastAPI
from fastapi import Request
from jwt.jwk import jwk_from_public_bytes
from jwt.jwt import JWT

from token_tango.config import KafkaConfig
from token_tango.excpetions import BadRequest
from token_tango.excpetions import Unauthorized
from token_tango.key_manager import KeyManager
from token_tango.key_rotation_consumer import KeyRotationConsumer
from token_tango.key_rotation_event import KeyRotationEvent


class JWTVerificationMiddleware:
    def __init__(self, app: FastAPI, key_rotation_config: KafkaConfig):
        self.app = app
        self.key_manager = KeyManager()
        self.key_rotation_consumer = KeyRotationConsumer(config=key_rotation_config)
        self.consumer_thread = Thread(target=self.kafka_consumer_thread, daemon=True)
        self.consumer_thread.start()
        self.jwt: JWT = JWT()  # type: ignore

    async def __call__(self, request: Request, call_next: Any) -> Any:
        jwt_access_token = self.extract_jwt_access_token(request=request)
        header_data = self.get_header_data(jwt_access_token=jwt_access_token)
        key_rotation_event = self.get_key_rotation_event(header_data=header_data)

        verifying_key = jwk_from_public_bytes(
            content=key_rotation_event.public_key.encode(),
            public_loader="load_pem_public_key",
        )
        claims: dict[str, Any] = self.jwt.decode(
            jwt_access_token,
            verifying_key,
            algorithms={"RSA"},
            do_time_check=True,
        )
        if not claims:
            raise Unauthorized(detail="Invalid JWT")

        request.state.claims = claims

        return await call_next(request)

    def extract_jwt_access_token(self, request: Request) -> str:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            raise Unauthorized(detail="Authorization header is missing")
        return auth_header.split("JWT ")[1]

    def get_header_data(self, jwt_access_token: str) -> dict[str, Any]:
        header_encoded = jwt_access_token.split(".")[0]
        header_str = base64.urlsafe_b64decode(f"{header_encoded}==").decode("utf-8")
        return json.loads(header_str)

    def get_key_id(self, header_data: dict[str, Any]) -> str:
        key_id = header_data.get("kid")
        if not key_id:
            raise BadRequest("Key ID 'kid' not found in JWT header")
        return key_id

    def get_key_rotation_event(self, header_data: dict[str, Any]) -> KeyRotationEvent:
        key_id = self.get_key_id(header_data=header_data)
        key_rotation_event = self.key_manager.get_key_by_id(key_id=key_id)
        if not key_rotation_event:
            raise Unauthorized(detail="Invalid key ID")
        return key_rotation_event

    def kafka_consumer_thread(self) -> None:
        for key_rotation_event in self.key_rotation_consumer.consume():
            self.key_manager.add_key(key_rotation_event)

        self.key_rotation_consumer.close()
