"""Secure chat client implementing control-plane, DH-based auth AES encryption,
session DH, signed messages, receipts, and transcript signing.
"""

import argparse
import json
import os
import socket
import sys
import time
from getpass import getpass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .common.protocol import Hello, ServerHello, DHClient, DHServer, Msg, Receipt
from .common.utils import now_ms, b64e, b64d, sha256_hex
from .crypto.aes import encrypt_aes_ecb_b64, decrypt_aes_ecb_b64
from .crypto.dh import gen_private_key, get_public_value, get_shared_secret, derive_key
from .crypto.pki import load_certificate, load_private_key, validate_certificate, get_common_name
from .crypto.sign import sign_message, verify_signature
from .storage.transcript import Transcript

import secrets
import hashlib

class SecureChatClient:
    def __init__(self, host: str, port: int, cert_path: str, key_path: str, ca_cert_path: str, server_cn: str):
        self.host = host
        self.port = port
        self.server_cn = server_cn

        self.cert = load_certificate(cert_path)
        self.private_key = load_private_key(key_path)
        self.ca_cert = load_certificate(ca_cert_path)

        self.sock: Optional[socket.socket] = None
        self.session_key: Optional[bytes] = None
        self.server_cert: Optional[x509.Certificate] = None
        self.transcript: Optional[Transcript] = None
        self.seq = 0

    def connect_and_negotiate(self, username: str) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))

            hello = {
                "client": get_common_name(self.cert),
                "ts": now_ms(),
                "client_cert": self.cert.public_bytes(encoding=serialization.Encoding.PEM).decode(),
                "nonce": b64e(secrets.token_bytes(16))
            }
            
            self.sock.send(json.dumps(hello).encode())

            data = self.sock.recv(8192)
            if not data:
                return False

            server_hello_json = json.loads(data.decode())
            server_cert_pem = server_hello_json.get("server_cert")
            if not server_cert_pem:
                print("Missing server certificate")
                return False

            server_cert = x509.load_pem_x509_certificate(server_cert_pem.encode())
            try:
                validate_certificate(server_cert, self.ca_cert)
            except Exception as e:
                print(f"Server cert validation failed: {e}")
                return False

            if get_common_name(server_cert) != self.server_cn:
                print(f"Server CN mismatch: expected {self.server_cn} got {get_common_name(server_cert)}")
                return False

            self.server_cert = server_cert
            print("Connected!")

            priv = gen_private_key()
            pub = get_public_value(priv)
            dh_temp = {"type": "dh_temp", "A": str(pub)}
            self.sock.send(json.dumps(dh_temp).encode())

            data = self.sock.recv(8192)
            if not data:
                return False

            dh_server = json.loads(data.decode())
            if dh_server.get("type") != "dh_temp":
                print("Expected dh_temp reply")
                return False

            server_B = int(dh_server["B"])
            shared = get_shared_secret(priv, server_B)
            self.temp_key = derive_key(shared)

            session_id = f"{username}-{self.server_cn}-{hello['ts']}"
            self.transcript = Transcript(session_id)
            self.transcript.append(hello)
            self.transcript.append(server_hello_json)

            return True

        except Exception as e:
            print(f"Connection failed: {e}")
            if self.sock:
                self.sock.close()
                self.sock = None
            return False

    def register_or_login(self, is_register: bool, username: str) -> bool:
        try:
            password = getpass(f"Enter password for {username}: ")
            if not password:
                print("Password cannot be empty")
                return False

            payload = {"username": username, "password": password}
            ciphertext = encrypt_aes_ecb_b64(self.temp_key, json.dumps(payload).encode())
            msg = {"type": "register" if is_register else "login", "payload": ciphertext}
            self.sock.send(json.dumps(msg).encode())

            data = self.sock.recv(8192)
            if not data:
                print("No response from server")
                return False
            resp = json.loads(data.decode())
            if "error" in resp:
                print(f"Server error: {resp['error']}")
                return False
            return True

        except Exception as e:
            print(f"Auth failed: {e}")
            return False

    def perform_session_dh(self) -> bool:
        try:
            priv = gen_private_key()
            pub = get_public_value(priv)
            self.sock.send(json.dumps({"type": "dh_session", "A": str(pub)}).encode())

            data = self.sock.recv(8192)
            if not data:
                return False
            dh_server = json.loads(data.decode())
            if dh_server.get("type") != "dh_session":
                print("expected dh_session")
                return False

            server_B = int(dh_server["B"])
            signature_b64 = dh_server.get("signature")

            shared = get_shared_secret(priv, server_B)
            self.session_key = derive_key(shared)

            self.transcript.append(DHClient(e=str(pub)))

            exported_before_dhserver = self.transcript.export_for_signing()
            exported_json = json.dumps(
                exported_before_dhserver, sort_keys=True, separators=(",", ":")
            ).encode()

            if not verify_signature(self.server_cert.public_key(), exported_json, b64d(signature_b64)):
                print("Invalid transcript signature from server")
                return False

            print("✓ Server signature verified successfully!")

            self.transcript.append(DHServer(f=str(server_B), signature=signature_b64))
            return True

        except Exception as e:
            print(f"Session DH failed: {e}")
            return False

    def send_message(self, text: str) -> bool:
        try:
            self.seq += 1
            ts = now_ms()
            ct_b64 = encrypt_aes_ecb_b64(self.session_key, text.encode())

            digest = hashlib.sha256(f"{self.seq}{ts}{ct_b64}".encode()).digest()
            sig = sign_message(self.private_key, digest)

            msg_to_send = {
                "type": "msg",
                "seq": self.seq,
                "ts": ts,
                "payload": ct_b64,
                "signature": b64e(sig)
            }

            self.sock.send(json.dumps(msg_to_send).encode())
            self.transcript.append(Msg(seq=self.seq, ts=ts, payload=ct_b64, signature=b64e(sig)))

            data = self.sock.recv(8192)
            if not data:
                print("No receipt received")
                return False

            receipt_json = json.loads(data.decode())
            receipt = Receipt(**receipt_json)

            if receipt.seq != self.seq:
                #print(f"Receipt seq mismatch: got {receipt.seq}, expected {self.seq}")
                return False

            receipt_data = f"{self.transcript.session_id}:{receipt.seq}".encode()
            if not verify_signature(self.server_cert.public_key(), receipt_data, b64d(receipt.signature)):
                print("Invalid receipt signature")
                return False

            self.transcript.append(receipt)
            return True

        except Exception as e:
            print(f"Send failed: {e}")
            return False

    def close(self):
        if self.sock:
            self.sock.close()

        if self.transcript:
            exported = self.transcript.export_for_signing()
            exported_json = json.dumps(exported, sort_keys=True, separators=(",", ":")).encode()
            final_sig = sign_message(self.private_key, exported_json)
            sig_path = Path(f"{self.transcript.path}.sig")
            with open(sig_path, "wb") as f:
                f.write(final_sig)
            print(f"Signed transcript saved to {sig_path}")


def main():
        parser = argparse.ArgumentParser(description="Run secure chat client")
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=9000)
        parser.add_argument("--cert", default="certs/client/client.crt")
        parser.add_argument("--key", default="certs/client/client.key")
        parser.add_argument("--ca-cert", default="certs/ca/ca.crt")
        parser.add_argument("--server-cn", default="server.local")
        parser.add_argument("--register", action="store_true")
        parser.add_argument("username")
        args = parser.parse_args()

        client = SecureChatClient(args.host, args.port, args.cert, args.key, args.ca_cert, args.server_cn)

        try:
            print(f"Connecting to {args.host}:{args.port}...")
            if not client.connect_and_negotiate(args.username):
                sys.exit(1)

            if not client.register_or_login(args.register, args.username):
                sys.exit(1)
            print("Authentication successful!")

            print("Performing session DH...")
            if not client.perform_session_dh():
                sys.exit(1)
            print("Secure channel established!")

            print("\nEnter messages (Ctrl+C to quit):")
            while True:
                try:
                    text = input("> ")
                    if text:
                        ok = client.send_message(text)
                        if ok:
                            print("✓ Message sent and receipt verified")
                        else:
                            print("✗ Failed to send/verify message")
                except KeyboardInterrupt:
                    break

        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
        finally:
            print("\nClosing connection...")
            client.close()


if __name__ == "__main__":
    main()
