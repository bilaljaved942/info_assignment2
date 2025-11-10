"""AES-128 ECB mode helpers with PKCS#7 padding.

This module provides small, well-tested helpers used by the assignment:
- pkcs7_pad / pkcs7_unpad
- encrypt_aes_ecb / decrypt_aes_ecb (bytes in/out)
- encrypt_aes_ecb_b64 / decrypt_aes_ecb_b64 (base64-friendly wrappers)

IMPORTANT: ECB is used here because the assignment skeleton expects it
for pedagogical reasons. Do not use ECB for real-world encryption.
"""

from typing import Optional
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


BLOCK_SIZE = 16


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
	"""Apply PKCS#7 padding to `data` to make its length a multiple of block_size."""
	if block_size <= 0 or block_size > 255:
		raise ValueError("invalid block size")
	pad_len = block_size - (len(data) % block_size)
	return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
	"""Remove PKCS#7 padding. Raises ValueError on invalid padding."""
	if not data or len(data) % block_size != 0:
		raise ValueError("invalid padded data length")
	pad_len = data[-1]
	if pad_len == 0 or pad_len > block_size:
		raise ValueError("invalid padding byte")
	if data[-pad_len:] != bytes([pad_len]) * pad_len:
		raise ValueError("invalid PKCS#7 padding")
	return data[:-pad_len]


def _validate_key(key: bytes) -> None:
	if not isinstance(key, (bytes, bytearray)):
		raise TypeError("key must be bytes")
	if len(key) not in (16, 24, 32):
		# assignment expects AES-128, but accept other sizes for flexibility
		raise ValueError("invalid AES key size (expected 16/24/32 bytes)")


def encrypt_aes_ecb(key: bytes, plaintext: bytes) -> bytes:
	"""Encrypt `plaintext` using AES-ECB with PKCS#7 padding. Returns raw ciphertext bytes."""
	_validate_key(key)
	padded = pkcs7_pad(plaintext, BLOCK_SIZE)
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	encryptor = cipher.encryptor()
	return encryptor.update(padded) + encryptor.finalize()


def decrypt_aes_ecb(key: bytes, ciphertext: bytes) -> bytes:
	"""Decrypt raw `ciphertext` using AES-ECB and remove PKCS#7 padding. Returns plaintext bytes."""
	_validate_key(key)
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	decryptor = cipher.decryptor()
	padded = decryptor.update(ciphertext) + decryptor.finalize()
	return pkcs7_unpad(padded, BLOCK_SIZE)


def encrypt_aes_ecb_b64(key: bytes, plaintext: bytes) -> str:
	"""Encrypt and return base64-encoded ciphertext (ASCII string)."""
	ct = encrypt_aes_ecb(key, plaintext)
	return base64.b64encode(ct).decode("ascii")


def decrypt_aes_ecb_b64(key: bytes, b64cipher: str) -> bytes:
	"""Decode base64 ciphertext and decrypt, returning plaintext bytes."""
	ct = base64.b64decode(b64cipher.encode("ascii"))
	return decrypt_aes_ecb(key, ct)


__all__ = [
	"pkcs7_pad",
	"pkcs7_unpad",
	"encrypt_aes_ecb",
	"decrypt_aes_ecb",
	"encrypt_aes_ecb_b64",
	"decrypt_aes_ecb_b64",
]

