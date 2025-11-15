"""Append-only transcript with hash chaining for integrity."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..common.utils import now_ms, sha256_hex
from ..crypto.sign import sign_message


def normalize_message(msg: Any) -> Dict[str, Any]:
    """
    Convert any protocol object (including Pydantic models) into a pure dict
    that is JSON-serializable and canonical.

    CRITICAL FIX: Completely exclude model_config and other internal Pydantic fields.
    """
    result = None
    
    if hasattr(msg, "model_dump"):      # Pydantic v2
        # Get the dict representation
        result = msg.model_dump(mode='json')
    elif hasattr(msg, "dict"):          # Pydantic v1 fallback
        result = msg.dict()
    elif isinstance(msg, dict):         # Already dict
        result = msg.copy()
    else:
        raise TypeError(f"Message of type {type(msg)} is not serializable")
    
    # CRITICAL: Recursively remove ALL model_config keys at any level
    def clean_dict(d):
        if isinstance(d, dict):
            # Remove model_config and recursively clean nested dicts
            cleaned = {}
            for k, v in d.items():
                if k == 'model_config':
                    continue  # Skip model_config entirely
                if isinstance(v, dict):
                    cleaned[k] = clean_dict(v)
                elif isinstance(v, list):
                    cleaned[k] = [clean_dict(item) if isinstance(item, dict) else item for item in v]
                else:
                    cleaned[k] = v
            return cleaned
        return d
    
    return clean_dict(result)


class TranscriptEntry:
    """A single transcript entry with message and metadata."""

    def __init__(self, message: Any, timestamp: Optional[int] = None):
        # Convert to canonical JSON-serializable dict and remove model_config
        msg_dict = normalize_message(message)

        self.message = msg_dict
        self.timestamp = timestamp or now_ms()

        # Canonical JSON representation (sorted keys!)
        self.json = json.dumps(msg_dict, sort_keys=True, separators=(",", ":"))

        # Hash the canonical form
        self.hash = sha256_hex(self.json.encode("utf-8"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "message": self.message,
            "hash": self.hash,
        }


class Transcript:
    """Append-only transcript with a hash chain for integrity."""

    def __init__(self, session_id: str, base_dir: str = "transcripts"):
        self.session_id = session_id
        self.base_dir = Path(base_dir)
        self.entries: List[TranscriptEntry] = []
        self.current_hash = ""

        self.base_dir.mkdir(exist_ok=True)
        self.path = self.base_dir / f"{session_id}.json"

        # Don't auto-load existing transcripts to avoid duplication
        # if self.path.exists():
        #     self.load()

    def append(self, message: Any) -> str:
        """Append a new message and update the hash chain."""

        entry = TranscriptEntry(message)

        # Hash chain: new_hash = SHA256(prev_hash || entry_hash)
        chain_input = f"{self.current_hash}{entry.hash}".encode("utf-8")
        self.current_hash = sha256_hex(chain_input)

        self.entries.append(entry)
        self.save()

        print(f"[DEBUG] transcript append: message hash={entry.hash}, chain={self.current_hash}")
        return self.current_hash

    def save(self) -> None:
        """Save transcript to file."""
        data = self.export()
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self) -> None:
        """Load transcript from file and verify hash chain."""
        with open(self.path) as f:
            data = json.load(f)

        self.entries = []
        self.current_hash = ""

        for e in data["entries"]:
            entry = TranscriptEntry(e["message"], e["timestamp"])

            # Validate stored hash
            if entry.hash != e["hash"]:
                raise ValueError("Transcript entry hash mismatch")

            # Update chain
            chain_input = f"{self.current_hash}{entry.hash}".encode("utf-8")
            self.current_hash = sha256_hex(chain_input)

            self.entries.append(entry)

        if self.current_hash != data["hash"]:
            raise ValueError("Transcript hash chain mismatch")

    def export(self) -> Dict[str, Any]:
        """Export full transcript with timestamps for storage."""
        return {
            "session_id": self.session_id,
            "created_at": self.entries[0].timestamp if self.entries else now_ms(),
            "hash": self.current_hash,
            "entries": [e.to_dict() for e in self.entries],
        }

    def export_for_signing(self) -> Dict[str, Any]:
        """
        Export a deterministic JSON form for signing.
        Excludes timestamps so client/server produce identical JSON.
        
        CRITICAL: This must produce IDENTICAL output on both client and server
        for the same sequence of messages.
        """
        return {
            "session_id": self.session_id,
            "entries": [
                {"hash": e.hash, "message": e.message}
                for e in self.entries
            ],
            "hash": self.current_hash,
        }

    def verify_hash_chain(self) -> bool:
        """Verify the integrity of the hash chain."""
        current = ""
        for e in self.entries:
            chain_input = f"{current}{e.hash}".encode("utf-8")
            current = sha256_hex(chain_input)
        return current == self.current_hash


def sign_transcript(private_key_path: Union[str, Path], transcript_data: Dict[str, Any]) -> bytes:
    """Sign a transcript using a private key."""
    from ..crypto.sign import load_private_key

    canonical = json.dumps(transcript_data, sort_keys=True, separators=(",", ":"))
    key = load_private_key(private_key_path)
    return sign_message(key, canonical.encode("utf-8"))