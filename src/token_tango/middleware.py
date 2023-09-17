import base64
import json
from threading import Thread
from typing import Any

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Request
from jwt.jwk import jwk_from_public_bytes
from jwt.jwt import JWT

from token_tango.config import KafkaConfig
from token_tango.key_manager import KeyManager
from token_tango.key_rotation_consumer import KeyRotationConsumer


class JWTVerificationMiddleware:
    def __init__(self, app: FastAPI, key_rotation_config: KafkaConfig):
        self.app = app
        self.key_manager = KeyManager()
        self.key_rotation_consumer = KeyRotationConsumer(config=key_rotation_config)
        self.consumer_thread = Thread(target=self.kafka_consumer_thread, daemon=True)
        self.consumer_thread.start()
        self.jwt = JWT()

    async def __call__(self, request: Request, call_next):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Token missing")

        access_token = auth_header.split("JWT ")[1]
        header_encoded = access_token.split(".")[0]

        header_str = base64.urlsafe_b64decode(header_encoded + "==").decode("utf-8")
        header_data = json.loads(header_str)

        key_id = header_data.get("kid")
        if not key_id:
            raise HTTPException(status_code=400, detail="key_id (kid) not found in JWT header")
        key_rotation_event = self.key_manager.get_key_by_id(key_id)
        if not key_rotation_event:
            raise HTTPException(status_code=401, detail="Invalid key ID")

        access_token = auth_header.split("JWT ")[1]
        verifying_key = jwk_from_public_bytes(content=access_token.encode(), public_loader="load_pem_public_key")
        claims: dict[str, Any] = self.jwt.decode(
            access_token,
            verifying_key,
            algorithms={"RSA"},
            do_time_check=True,
        )
        if not claims:
            raise HTTPException(status_code=401, detail="Invalid JWT")

        print(claims)
        request.state.claims = claims

        return await call_next(request)

    def kafka_consumer_thread(self):
        for key_rotation_event in self.key_rotation_consumer.consume():
            self.key_manager.add_key(key_rotation_event)

        self.key_rotation_consumer.close()
