"""Secure chat server - implements PKI, DH, and message transcripts.

This server:
1. Accepts TCP connections (no TLS - crypto is at app layer)
2. Validates client certs and handles authentication
3. Performs DH key exchange with transcript signatures
4. Encrypts/decrypts messages with session keys
5. Maintains signed session transcripts
"""

import argparse
import json
import os
import socket
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from .common.protocol import (
    Hello, ServerHello, Register, Login,
    DHClient, DHServer, Msg, Receipt
)
from .common.utils import now_ms, b64e, b64d, sha256_hex
from .crypto.aes import encrypt_aes_ecb_b64, decrypt_aes_ecb_b64
from .crypto.dh import (
    gen_private_key, get_public_value,
    get_shared_secret, derive_key
)
from .crypto.pki import (
    load_certificate, load_private_key,
    validate_certificate, get_common_name
)
from .crypto.sign import sign_message
from .storage.db import Database
from .storage.transcript import Transcript


class SecureChatServer:
    """Main server implementation."""

    def __init__(
        self,
        host: str,
        port: int,
        cert_path: str,
        key_path: str,
        ca_cert_path: str
    ):
        self.host = host
        self.port = port
        
        # Load certificates
        self.cert = load_certificate(cert_path)
        self.private_key = load_private_key(key_path)
        self.ca_cert = load_certificate(ca_cert_path)
        
        # Track active sessions
        self.sessions: Dict[str, Tuple[bytes, Transcript]] = {}
        
        # Database for user authentication
        self.db = Database()

    def run(self):
        """Run the server loop."""
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

    def handle_client(self, sock: socket.socket, addr: Tuple[str, int]):
        """Handle a client connection through the full protocol flow."""
        peer = f"{addr[0]}:{addr[1]}"
        print(f"New connection from {peer}")
        
        # Receive initial Hello
        data = sock.recv(4096)
        if not data:
            return
            
        hello = Hello.model_validate_json(data)
        print(f"Got Hello from {hello.client}")
        
        # Send ServerHello
        server_hello = ServerHello(
            server=get_common_name(self.cert),
            ts=now_ms()
        )
        sock.send(server_hello.model_dump_json().encode())
        
        # Handle login/registration
        data = sock.recv(4096)
        if not data:
            return
            
        msg = json.loads(data)
        if "username" not in msg:
            print(f"Invalid auth message from {peer}")
            return
            
        username = msg["username"]
        password = msg["password"]
        
        if "register" in msg:
            # New user registration
            if not self.db.add_user(username, password):
                print(f"Username {username} already exists")
                return
            print(f"Registered new user: {username}")
        else:
            # Existing user login
            if not self.db.verify_user(username, password):
                print(f"Invalid credentials for {username}")
                return
            print(f"User {username} logged in")
        
        # Start transcript for this session
        session_id = f"{username}-{now_ms()}"
        transcript = Transcript(session_id)
        transcript.append(hello)
        transcript.append(server_hello)
        
        # Receive client's DH key
        data = sock.recv(4096)
        if not data:
            return
            
        dh_client = DHClient.model_validate_json(data)
        transcript.append(dh_client)
        
        # Generate our DH key and derive shared secret
        priv = gen_private_key()
        pub = get_public_value(priv)
        shared = get_shared_secret(priv, int(b64d(dh_client.e).hex(), 16))
        
        # Sign the transcript so far
        transcript_data = transcript.export()
        signature = sign_message(self.private_key, 
                               json.dumps(transcript_data).encode())
        
        # Send our DH key and transcript signature
        dh_server = DHServer(
            f=b64e(hex(pub)[2:].encode()),
            signature=b64e(signature)
        )
        sock.send(dh_server.model_dump_json().encode())
        transcript.append(dh_server)
        
        # Derive final AES key
        key = derive_key(shared)
        
        # Store session
        self.sessions[session_id] = (key, transcript)
        
        # Handle messages
        seq = 0
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                    
                msg = Msg.model_validate_json(data)
                if msg.seq != seq + 1:
                    print(f"Invalid sequence number from {peer}")
                    break
                    
                # Decrypt and print message
                plaintext = decrypt_aes_ecb_b64(key, msg.payload)
                print(f"Message from {username}: {plaintext.decode()}")
                
                # Store in transcript
                transcript.append(msg)
                
                # Send signed receipt
                receipt = Receipt(
                    seq=msg.seq,
                    signature=b64e(sign_message(
                        self.private_key,
                        f"{session_id}:{msg.seq}".encode()
                    ))
                )
                sock.send(receipt.model_dump_json().encode())
                transcript.append(receipt)
                
                seq = msg.seq
                
            except Exception as e:
                print(f"Error handling message from {peer}: {e}")
                break
        
        print(f"Client {peer} disconnected")
        if session_id in self.sessions:
            del self.sessions[session_id]


def main():
    """Parse args and start server."""
    parser = argparse.ArgumentParser(description="Run the secure chat server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9000, help="Port to listen on")
    parser.add_argument(
        "--cert",
        default="certs/server/server.crt",
        help="Path to server certificate"
    )
    parser.add_argument(
        "--key",
        default="certs/server/server.key",
        help="Path to server private key"
    )
    parser.add_argument(
        "--ca-cert",
        default="certs/ca/ca.crt",
        help="Path to CA certificate"
    )
    args = parser.parse_args()
    
    server = SecureChatServer(
        args.host,
        args.port,
        args.cert,
        args.key,
        args.ca_cert
    )
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down")
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
