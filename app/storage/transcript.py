"""Append-only transcript with hash chaining for integrity.

This module provides an append-only message transcript that:
1. Stores all protocol messages (JSON) with timestamps
2. Maintains a hash chain for integrity verification
3. Supports export/import for offline verification
4. Signs the final state for non-repudiation

Usage:
    transcript = Transcript("chat-123")
    transcript.append(msg1)  # stores message and updates hash
    transcript.append(msg2)
    
    # Export for verification
    data = transcript.export()
    sig = sign_transcript(private_key, data)
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..common.utils import now_ms, sha256_hex
from ..crypto.sign import sign_message


class TranscriptEntry:
    """A single transcript entry with message and metadata."""
    
    def __init__(self, message: Any, timestamp: Optional[int] = None):
        """Create a new transcript entry.
        
        Args:
            message: The message to store (must be JSON-serializable)
            timestamp: Optional timestamp (default: current time in ms)
        """
        self.message = message
        self.timestamp = timestamp or now_ms()
        
        # Convert message to canonical JSON and get its hash
        self.json = json.dumps(
            message.model_dump() if hasattr(message, "model_dump") else message,
            sort_keys=True,
        )
        self.hash = sha256_hex(self.json.encode("utf-8"))

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to a dictionary for export."""
        return {
            "timestamp": self.timestamp,
            "message": json.loads(self.json),
            "hash": self.hash,
        }


class Transcript:
    """Append-only transcript with hash chaining."""

    def __init__(self, session_id: str, base_dir: str = "transcripts"):
        """Create or load a transcript.
        
        Args:
            session_id: Unique identifier for this chat session
            base_dir: Base directory for transcript storage
        """
        self.session_id = session_id
        self.base_dir = Path(base_dir)
        self.entries: List[TranscriptEntry] = []
        self.current_hash = ""  # hash chain head
        
        # Ensure transcript directory exists
        self.base_dir.mkdir(exist_ok=True)
        self.path = self.base_dir / f"{session_id}.json"
        
        # Load existing transcript if any
        if self.path.exists():
            self.load()

    def append(self, message: Any) -> str:
        """Append a message to the transcript and update hash chain.
        
        Args:
            message: The message to append (must be JSON-serializable)
            
        Returns:
            The new transcript hash after appending
        """
        entry = TranscriptEntry(message)
        
        # Update hash chain: hash(prev_hash || entry_hash)
        input_bytes = f"{self.current_hash}{entry.hash}".encode("utf-8")
        self.current_hash = sha256_hex(input_bytes)
        
        self.entries.append(entry)
        self.save()
        
        return self.current_hash

    def save(self) -> None:
        """Save transcript to disk."""
        data = self.export()
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self) -> None:
        """Load transcript from disk and verify hash chain."""
        with open(self.path) as f:
            data = json.load(f)
        
        self.entries = []
        self.current_hash = ""
        
        # Reconstruct and verify hash chain
        for entry_data in data["entries"]:
            entry = TranscriptEntry(
                entry_data["message"],
                entry_data["timestamp"]
            )
            if entry.hash != entry_data["hash"]:
                raise ValueError("transcript entry hash mismatch")
            
            # Update hash chain
            input_bytes = f"{self.current_hash}{entry.hash}".encode("utf-8")
            self.current_hash = sha256_hex(input_bytes)
            
            self.entries.append(entry)
        
        if self.current_hash != data["hash"]:
            raise ValueError("transcript hash chain mismatch")

    def export(self) -> Dict[str, Any]:
        """Export transcript data for storage/verification."""
        return {
            "session_id": self.session_id,
            "created_at": self.entries[0].timestamp if self.entries else now_ms(),
            "hash": self.current_hash,
            "entries": [e.to_dict() for e in self.entries],
        }

    def verify_hash_chain(self) -> bool:
        """Verify transcript hash chain integrity."""
        current = ""
        for entry in self.entries:
            input_bytes = f"{current}{entry.hash}".encode("utf-8")
            current = sha256_hex(input_bytes)
        return current == self.current_hash


def sign_transcript(
    private_key_path: Union[str, Path],
    transcript_data: Dict[str, Any]
) -> bytes:
    """Sign a transcript export for non-repudiation.
    
    Args:
        private_key_path: Path to signer's private key
        transcript_data: Transcript data from export()
        
    Returns:
        RSA signature over the canonical JSON transcript
    """
    from ..crypto.sign import load_private_key
    
    # Convert to canonical JSON (sorted keys, no whitespace)
    json_data = json.dumps(transcript_data, sort_keys=True, separators=(",", ":"))
    
    # Load key and sign
    key = load_private_key(private_key_path)
    return sign_message(key, json_data.encode("utf-8"))


if __name__ == "__main__":
    # Test transcript functionality
    from ..common.protocol import Hello, Msg
    from ..common.utils import b64e
    
    print("Testing transcript...")
    
    # Create test messages
    hello = Hello(client="test.local", ts=now_ms())
    msg1 = Msg(seq=1, payload=b64e(b"test message 1"))
    msg2 = Msg(seq=2, payload=b64e(b"test message 2"))
    
    # Create transcript and append messages
    t = Transcript("test-session")
    h1 = t.append(hello)
    h2 = t.append(msg1)
    h3 = t.append(msg2)
    
    print(f"Final hash: {h3}")
    print(f"Stored at: {t.path}")
    
    # Verify hash chain
    valid = t.verify_hash_chain()
    print(f"Hash chain valid: {valid}")
    
    # Test export and signing
    data = t.export()
    sig = sign_transcript("certs/server/server.key", data)
    print(f"Exported and signed {len(t.entries)} messages")
