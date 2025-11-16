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

        self.cert = load_certificate(cert_path)
        self.private_key = load_private_key(key_path)
        self.ca_cert = load_certificate(ca_cert_path)

        self.db = Database()
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
            data = conn.recv(8192)
            if not data:
                return
            hello_json = json.loads(data.decode())
            hello = Hello(**hello_json)

            client_cert_pem = hello_json.get("client_cert")
            if not client_cert_pem:
                conn.send(json.dumps({"error": "Missing client certificate"}).encode())
                return

            client_cert = load_certificate_bytes(client_cert_pem.encode())
            try:
                validate_certificate(client_cert, self.ca_cert)
            except Exception as e:
                conn.send(json.dumps({"error": f"BAD CERT: {e}"}).encode())
                return

            print(f"Got Hello from {get_common_name(client_cert)}")

            server_nonce = b64e(secrets.token_bytes(16))
            server_hello = {
                "type": "server_hello",
                "server": get_common_name(self.cert),
                "ts": now_ms(),
                "server_cert": self.cert.public_bytes(encoding=serialization.Encoding.PEM).decode(),
                "nonce": server_nonce
            }
            conn.send(json.dumps(server_hello).encode())

            data = conn.recv(8192)
            if not data:
                return
            dh_client_json = json.loads(data.decode())
            if dh_client_json.get("type") != "dh_temp":
                conn.send(json.dumps({"error": "expected dh_temp"}).encode())
                return

            priv = gen_private_key()
            pub = get_public_value(priv)

            client_A = int(dh_client_json["A"])
            shared = get_shared_secret(priv, client_A)
            temp_key = derive_key(shared)

            dh_server = {"type": "dh_temp", "B": str(pub)}
            conn.send(json.dumps(dh_server).encode())

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

            username = auth_data.get("username")
            password = auth_data.get("password")
            if not username or not password:
                conn.send(json.dumps({"error": "missing credentials"}).encode())
                return

            if auth_msg["type"] == "register":
                if not self.db.add_user(username, password):
                    conn.send(json.dumps({"error": "username taken"}).encode())
                    return
            else:
                if not self.db.verify_user(username, password):
                    conn.send(json.dumps({"error": "invalid credentials"}).encode())
                    return

            conn.send(json.dumps({"success": True}).encode())

            session_id = f"{username}-{get_common_name(self.cert)}-{hello_json['ts']}"
            transcript = Transcript(session_id)
            transcript.append(hello_json)
            transcript.append(server_hello)

            #print(f"[DEBUG] After Hello/ServerHello, transcript has {len(transcript.entries)} entries")

            data = conn.recv(8192)
            if not data:
                return
            dh_client_session = json.loads(data.decode())
            if dh_client_session.get("type") != "dh_session":
                conn.send(json.dumps({"error": "expected dh_session"}).encode())
                return

            a_pub = int(dh_client_session["A"])

            s_priv = gen_private_key()
            s_pub = get_public_value(s_priv)
            shared_session = get_shared_secret(s_priv, a_pub)
            session_key = derive_key(shared_session)

            transcript.append(DHClient(e=str(a_pub)))
            #print(f"[DEBUG] After DHClient, transcript has {len(transcript.entries)} entries")

            exported_before_dhserver = transcript.export_for_signing()
            exported_json = json.dumps(
                exported_before_dhserver,
                sort_keys=True,
                separators=(",", ":")
            ).encode()

            #print(f"[DEBUG] Signing transcript with {len(transcript.entries)} entries")
            #print(f"[DEBUG] server signing sha256: {sha256_hex(exported_json)}")

            sig = sign_message(self.private_key, exported_json)
            sig_b64 = b64e(sig)

            final_dh_server = DHServer(f=str(s_pub), signature=sig_b64)
            transcript.append(final_dh_server)

            #print(f"[DEBUG] After DHServer, transcript has {len(transcript.entries)} entries")

            dh_server_session = {"type": "dh_session", "B": str(s_pub), "signature": sig_b64}
            conn.send(json.dumps(dh_server_session).encode())

            self.sessions[transcript.session_id] = (session_key, transcript, client_cert)

            seq_expected = 0
            while True:
                data = conn.recv(8192)
                if not data:
                    break
                msg_json = json.loads(data.decode())
                if msg_json.get("type") != "msg":
                    continue

                msg = Msg(**msg_json)

                if msg.seq != seq_expected + 1:
                    print(f"Invalid sequence: {msg.seq} expected {seq_expected + 1}")
                    break

                digest_bytes = __import__("hashlib").sha256(
                    f"{msg.seq}{msg.ts}{msg.payload}".encode()
                ).digest()

                sender_pub = client_cert.public_key()
                if not verify_signature(sender_pub, digest_bytes, b64d(msg.signature)):
                    print("Message signature verification failed")
                    break

                try:
                    plaintext = decrypt_aes_ecb_b64(session_key, msg.payload).decode()
                except Exception as e:
                    print(f"decrypt fail: {e}")
                    break

                print(f"[{username}] {plaintext}")
                transcript.append(msg)
                seq_expected = msg.seq

                receipt_sig = sign_message(
                    self.private_key,
                    f"{transcript.session_id}:{seq_expected}".encode()
                )
                receipt = Receipt(seq=seq_expected, signature=b64e(receipt_sig))

                conn.send(json.dumps(receipt.dict()).encode())
                transcript.append(receipt)

            final_export = transcript.export_for_signing()
            final_json = json.dumps(
                final_export,
                sort_keys=True,
                separators=(",", ":")
            ).encode()

            #print(f"[DEBUG] server final transcript sha256: {sha256_hex(final_json)}")
            #print(f"[DEBUG] server final transcript JSON: {final_json.decode()}")

            final_sig = sign_message(self.private_key, final_json)
            sig_path = Path(f"{transcript.path}.sig")
            with open(sig_path, "wb") as f:
                f.write(final_sig)
            print(f"Saved transcript signature to {sig_path}")

        except Exception as e:
            print(f"Error handling client {addr}: {e}")
            import traceback
            traceback.print_exc()


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
        print("\nShutting down")
    except Exception as e:
        print(f"Server error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
