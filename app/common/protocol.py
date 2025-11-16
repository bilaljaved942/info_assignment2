"""Pydantic models for application-layer messages.

These models are intentionally simple and serve as the canonical
JSON shapes for messages exchanged between client and server.

Fields are kept generic (strings/ints) so the rest of the skeleton can
operate on base64-encoded binary fields (e.g. DH public values,
encrypted payloads, signatures).
"""

from typing import Optional
from pydantic import BaseModel


from pydantic.config import ConfigDict

class Message(BaseModel):
    """Base class for all protocol messages."""
    model_config = ConfigDict(
        frozen=False,  # Allow field updates
        validate_assignment=True,  # Validate fields on assignment
        extra='forbid',  # Don't allow extra fields
        str_strip_whitespace=True,  # Strip whitespace from strings
        validate_default=True  # Validate default values
    )


class Hello(Message):
    """Client hello message.

    Contains the client identity, timestamp, certificate (PEM),
    and an optional random nonce for freshness.
    """
    client: str
    ts: int
    client_cert: Optional[str] = None
    nonce: Optional[str] = None


class ServerHello(Message):
    """Server hello message.

    Contains the server identity, timestamp, certificate (PEM),
    and an optional random nonce for freshness.
    """
    server: str
    ts: int
    server_cert: Optional[str] = None
    nonce: Optional[str] = None



class Register(Message):
    """Registration request."""
    type: str = "register"  # Fixed value
    username: str
    password: str


class Login(Message):
    """Login request."""
    type: str = "login"  # Fixed value
    username: str
    password: str


class DHClient(Message):
    """Client DH key."""
    # e: client's DH public value, base64-encoded
    e: str
    # optional nonce or additional data
    nonce: Optional[str] = None


class DHServer(Message):
    """Server DH key."""
    # f: server's DH public value, base64-encoded
    f: str
    # signature on the handshake or transcript (base64)
    signature: Optional[str] = None


class Msg(Message):
    """Encrypted message."""
    type: str = "msg"
    seq: int
    ts: int
    payload: str            # base64-encoded encrypted data
    signature: str          # base64-encoded signature



class Receipt(Message):
    """Message receipt."""
    seq: int
    signature: str  # base64-encoded signature

