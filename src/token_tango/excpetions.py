from http import HTTPStatus

from fastapi import HTTPException


class Unauthorized(HTTPException):
    def __init__(self, detail: str = "Unauthorized") -> None:
        super().__init__(HTTPStatus.UNAUTHORIZED, detail=detail)


class BadRequest(HTTPException):
    def __init__(self, detail: str = "Bad Request") -> None:
        super().__init__(HTTPStatus.BAD_REQUEST, detail=detail)
