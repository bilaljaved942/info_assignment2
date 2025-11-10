"""Small helper utilities used by the protocol and storage layers.

Provided:
- now_ms() -> int: current time in milliseconds
- b64e(b: bytes) -> str: base64 encode bytes to ASCII string
- b64d(s: str) -> bytes: base64 decode ASCII string to bytes
- sha256_hex(data) -> str: hex SHA-256 of bytes or string

Keep these helpers tiny and dependency-free so tests and early code
can run without bringing in heavy crypto libraries.
"""

from time import time
import base64
import hashlib
from typing import Union


def now_ms() -> int:
	"""Return current UNIX time in milliseconds (int)."""
	return int(time() * 1000)


def b64e(b: bytes) -> str:
	"""Base64-encode bytes and return an ASCII string.

	Uses standard padding-enabled base64 (safe for wire transport in JSON).
	"""
	return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
	"""Decode a base64 ASCII string into bytes."""
	return base64.b64decode(s.encode("ascii"))


def sha256_hex(data: Union[bytes, str]) -> str:
	"""Return the SHA-256 hex digest for `data` (bytes or str)."""
	if isinstance(data, str):
		data = data.encode("utf-8")
	return hashlib.sha256(data).hexdigest()
