"""Secure chat server implementing control-plane, DH, encrypted registration/login,
session DH, per-message signing/verification, receipts, transcripts and transcript signing.

Run:
    python -m app.server --host 127.0.0.1 --port 9000
"""
import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Tuple, Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .common.protocol import Hello, ServerHello, DHClient, DHServer, Msg, Receipt
from .common.utils import now_ms, b64e, b64d, sha256_hex
from .crypto.aes import encrypt_aes_ecb_b64, decrypt_aes_ecb_b64
from .crypto.dh import gen_private_key, get_public_value, get_shared_secret, derive_key
from .crypto.pki import load_certificate, load_private_key, validate_certificate, get_common_name
from .crypto.sign import sign_message, verify_signature
from .storage.db import Database
from .storage.transcript import Transcript

import secrets

class SecureChatServer:
    def __init__(self, host: str, port: int, cert_path: str, key_path: str, ca_cert_path: str):
        self.host = host
        self.port = port

        # load server identity and CA
        self.cert = load_certificate(cert_path)
        self.private_key = load_private_key(key_path)  # returns key object
        self.ca_cert = load_certificate(ca_cert_path)

        self.db = Database()
        # map session_id -> (session_key, transcript, peer_cert)
        self.sessions: Dict[str, Tuple[bytes, Transcript, x509.Certificate]] = {}

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)

        print(f"Server listening on {self.host}:{self.port}")
        print(f"Certificate CN: {get_common_name(self.cert)}")

        while True:
            client, addr = sock.accept()
            try:
                self.handle_client(client, addr)
            except Exception as e:
                print(f"Error handling client {addr}: {e}")
            finally:
                client.close()

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        print(f"New connection from {addr[0]}:{addr[1]}")
        try:
            # 1) Expect Hello with client certificate and nonce
            data = conn.recv(8192)
            if not data:
                return
            hello_json = json.loads(data.decode())
            hello = Hello(**hello_json)
            # hello.client_cert expected to be PEM string, hello.nonce base64
            client_cert_pem = hello_json.get("client_cert")
            if not client_cert_pem:
                conn.send(json.dumps({"error": "Missing client certificate"}).encode())
                return

            # Load client cert and validate it against CA
            client_cert = load_certificate_bytes(client_cert_pem.encode())
            try:
                validate_certificate(client_cert, self.ca_cert)
            except Exception as e:
                conn.send(json.dumps({"error": f"BAD CERT: {e}"}).encode())
                return

            print(f"Got Hello from {get_common_name(client_cert)}")

            # 2) Send ServerHello with our cert PEM and nonce
            server_nonce = b64e(secrets.token_bytes(16))
            server_hello = {
                "type": "server_hello",
                "server": get_common_name(self.cert),
                "ts": now_ms(),
                "server_cert": self.cert.public_bytes(encoding=serialization.Encoding.PEM).decode(),
                "nonce": server_nonce
            }
            conn.send(json.dumps(server_hello).encode())

            # 3) Perform ephemeral DH for control plane (authentication) - get client's ephemeral DH
            data = conn.recv(8192)
            if not data:
                return
            dh_client_json = json.loads(data.decode())
            if dh_client_json.get("type") != "dh_temp":
                conn.send(json.dumps({"error": "expected dh_temp"}).encode())
                return

            # server ephemeral DH
            priv = gen_private_key()
            pub = get_public_value(priv)
            # compute shared temp secret
            client_A = int(dh_client_json["A"])
            shared = get_shared_secret(priv, client_A)
            temp_key = derive_key(shared)  # 16 bytes

            # send dh_temp reply
            dh_server = {"type": "dh_temp", "B": str(pub)}
            conn.send(json.dumps(dh_server).encode())

            # 4) Receive encrypted auth payload (register/login) encrypted with temp_key
            data = conn.recv(8192)
            if not data:
                return
            auth_msg = json.loads(data.decode())
            if "type" not in auth_msg or "payload" not in auth_msg:
                conn.send(json.dumps({"error": "invalid auth payload"}).encode())
                return

            ciphertext_b64 = auth_msg["payload"]
            try:
                plaintext = decrypt_aes_ecb_b64(temp_key, ciphertext_b64).decode()
                auth_data = json.loads(plaintext)
            except Exception as e:
                conn.send(json.dumps({"error": f"decryption failed: {e}"}).encode())
                return

            # auth_data must have username and password (clear here); we'll salt/hash server-side
            username = auth_data.get("username")
            password = auth_data.get("password")
            if not username or not password:
                conn.send(json.dumps({"error": "missing credentials"}).encode())
                return

            # Register or login
            if auth_msg["type"] == "register":
                # Let Database handle salting and hashing
                if not self.db.add_user(username, password):
                    conn.send(json.dumps({"error": "username taken"}).encode())
                    return
            else:
                # login path: verify credentials using Database helper
                if not self.db.verify_user(username, password):
                    conn.send(json.dumps({"error": "invalid credentials"}).encode())
                    return

            # Send success
            conn.send(json.dumps({"success": True}).encode())

            # Start session transcript using the exact exchanged message dicts
            # Use deterministic session_id matching client: username-server-cn-timestamp
            session_id = f"{username}-{get_common_name(self.cert)}-{hello_json['ts']}"
            transcript = Transcript(session_id)
            # append the raw Hello JSON we received and the ServerHello dict we sent
            transcript.append(hello_json)
            transcript.append(server_hello)

            # 5) Perform session DH: receive client's session DH public
            data = conn.recv(8192)
            if not data:
                return
            dh_client_session = json.loads(data.decode())
            if dh_client_session.get("type") != "dh_session":
                conn.send(json.dumps({"error": "expected dh_session"}).encode())
                return

            a_pub = int(dh_client_session["A"])
            # server session private
            s_priv = gen_private_key()
            s_pub = get_public_value(s_priv)
            shared_session = get_shared_secret(s_priv, a_pub)
            session_key = derive_key(shared_session)  # AES session key (16 bytes)

            # append DHClient and DHServer to transcript BEFORE signing
            transcript.append(DHClient(e=str(a_pub)))
            # Prepare DHServer message with signature
            # First, create a temporary DHServer message without signature
            temp_dh_server = DHServer(f=str(s_pub), signature=None)
            transcript.append(temp_dh_server)

            # First sign the transcript with placeholder signature
            sig = sign_message(self.private_key, json.dumps(transcript.export_for_signing(), 
                                                          sort_keys=True, separators=(",", ":")).encode())
            
            # Update the DHServer entry with actual signature and re-export
            transcript.entries[-1].message.signature = b64e(sig)
            exported = transcript.export_for_signing()
            exported_json = json.dumps(exported, sort_keys=True, separators=(",", ":")).encode()

            try:
                from .common.utils import sha256_hex
                print(f"[DEBUG] server canonical transcript sha256: {sha256_hex(exported_json)}")
                print(f"[DEBUG] server canonical transcript JSON: {exported_json.decode()}")
            except Exception:
                pass

            # Send DH session with signature
            dh_server_session = {"type": "dh_session", "B": str(s_pub), "signature": b64e(sig)}
            conn.send(json.dumps(dh_server_session).encode())

            # store session
            self.sessions[transcript.session_id] = (session_key, transcript, client_cert)

            # 6) Now message loop: decrypt/verify incoming Msg objects, then sign receipt
            seq_expected = 0
            while True:
                data = conn.recv(8192)
                if not data:
                    break
                msg_json = json.loads(data.decode())
                if msg_json.get("type") != "msg":
                    # ignore unexpected or send error
                    continue

                msg = Msg(**msg_json)
                # check seq
                if msg.seq != seq_expected + 1:
                    print(f"Invalid sequence: {msg.seq} expected {seq_expected + 1}")
                    break

                # verify signature: recompute h = SHA256(seq||ts||ct)
                h_input = f"{msg.seq}{msg.ts}{msg.payload}".encode()
                h = sha256_hex(h_input).encode()
                sender_pub = client_cert.public_key()
                if not verify_signature(sender_pub, h_input if False else sha256_hex(h_input).encode(), b64d(msg.signature)) and False:
                    # The verify_signature implementation expects actual signature over bytes -- instead compute digest and use verify_signature properly.
                    pass
                # We'll verify correctly: recompute digest bytes
                digest_bytes = __import__("hashlib").sha256(f"{msg.seq}{msg.ts}{msg.payload}".encode()).digest()
                if not verify_signature(sender_pub, digest_bytes, b64d(msg.signature)):
                    print("Message signature verification failed")
                    break

                # decrypt ciphertext
                try:
                    plaintext = decrypt_aes_ecb_b64(session_key, msg.payload).decode()
                except Exception as e:
                    print(f"decrypt fail: {e}")
                    break

                print(f"[{username}] {plaintext}")
                transcript.append(msg)
                seq_expected = msg.seq

                # sign receipt and return
                receipt_sig = sign_message(self.private_key, f"{transcript.session_id}:{seq_expected}".encode())
                receipt = Receipt(seq=seq_expected, signature=b64e(receipt_sig))
                conn.send(json.dumps(receipt.model_dump()).encode())
                transcript.append(receipt)

            # session ended; sign final transcript and save
            # sign final transcript using the same canonical export
            final_export = transcript.export_for_signing()
            final_json = json.dumps(final_export, sort_keys=True, separators=(",", ":")).encode()
            try:
                from .common.utils import sha256_hex
                print(f"[DEBUG] server final transcript sha256: {sha256_hex(final_json)}")
                print(f"[DEBUG] server final transcript JSON: {final_json.decode()}")
            except Exception:
                pass
            final_sig = sign_message(self.private_key, final_json)
            sig_path = Path(f"{transcript.path}.sig")
            with open(sig_path, "wb") as f:
                f.write(final_sig)
            print(f"Saved transcript signature to {sig_path}")

        except Exception as e:
            print(f"Error handling client {addr}: {e}")

# helper: load cert from PEM bytes using cryptography
def load_certificate_bytes(pem_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_bytes)

def main():
    parser = argparse.ArgumentParser(description="Run secure chat server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--cert", default="certs/server/server.crt")
    parser.add_argument("--key", default="certs/server/server.key")
    parser.add_argument("--ca-cert", default="certs/ca/ca.crt")
    args = parser.parse_args()

    # ensure DB tables exist
    try:
        db = Database()
        db.initialize_tables()
        print("Database initialized")
    except Exception as e:
        print(f"Database init failed: {e}")
        sys.exit(1)

    try:
        server = SecureChatServer(args.host, args.port, args.cert, args.key, args.ca_cert)
        server.run()
    except KeyboardInterrupt:
        print("Shutting down")
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
