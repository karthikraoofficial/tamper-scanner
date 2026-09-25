import pytest

from tamper_scanner.storage import EncryptedArtifactStore


def test_encrypted_store_round_trips_bytes_without_exposing_plaintext(tmp_path) -> None:
    store = EncryptedArtifactStore(tmp_path, key="test-key")

    store.save("assessment-1", b"private bank statement")

    encrypted_path = tmp_path / "assessment-1.bin"
    assert encrypted_path.read_bytes() != b"private bank statement"
    assert store.load("assessment-1") == b"private bank statement"


def test_encrypted_store_requires_a_key(tmp_path) -> None:
    with pytest.raises(ValueError, match="encryption key"):
        EncryptedArtifactStore(tmp_path, key="")
