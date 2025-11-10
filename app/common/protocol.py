"""Pydantic models for application-layer messages.

These models are intentionally simple and serve as the canonical
JSON shapes for messages exchanged between client and server.

Fields are kept generic (strings/ints) so the rest of the skeleton can
operate on base64-encoded binary fields (e.g. DH public values,
encrypted payloads, signatures).
"""

from pydantic import BaseModel
from typing import Optional


class Hello(BaseModel):
	client: str
	ts: int


class ServerHello(BaseModel):
	server: str
	ts: int


class Register(BaseModel):
	username: str
	password: str


class Login(BaseModel):
	username: str
	password: str


class DHClient(BaseModel):
	# e: client's DH public value, base64-encoded
	e: str
	# optional nonce or additional data
	nonce: Optional[str] = None


class DHServer(BaseModel):
	# f: server's DH public value, base64-encoded
	f: str
	# signature on the handshake or transcript (base64)
	signature: Optional[str] = None


class Msg(BaseModel):
	seq: int
	# encrypted payload (base64)
	payload: str
	# optional MAC or HMAC (base64)
	mac: Optional[str] = None


class Receipt(BaseModel):
	seq: int
	signature: str

