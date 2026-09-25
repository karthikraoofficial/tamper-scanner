"""Encrypted local artifact retention."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class EncryptedArtifactStore:
    """Store document bytes encrypted with a deployment-provided key."""

    def __init__(self, root: Path, key: str) -> None:
        if not key:
            raise ValueError("An encryption key is required for encrypted retention.")
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)
        derived_key = base64.urlsafe_b64encode(hashlib.sha256(key.encode("utf-8")).digest())
        self._cipher = Fernet(derived_key)

    def save(self, artifact_id: str, content: bytes) -> None:
        self._path(artifact_id).write_bytes(self._cipher.encrypt(content))

    def load(self, artifact_id: str) -> bytes:
        try:
            return self._cipher.decrypt(self._path(artifact_id).read_bytes())
        except (FileNotFoundError, InvalidToken) as error:
            raise FileNotFoundError("Encrypted artifact not found.") from error

    def delete(self, artifact_id: str) -> None:
        self._path(artifact_id).unlink(missing_ok=True)

    def _path(self, artifact_id: str) -> Path:
        if not artifact_id or Path(artifact_id).name != artifact_id:
            raise ValueError("Invalid artifact ID.")
        return self._root / f"{artifact_id}.bin"