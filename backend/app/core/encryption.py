"""Encryption utilities for storing secrets securely."""
import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet
from app.config import settings


def _get_encryption_key() -> bytes:
    """
    Derive a Fernet-compatible key from the app's SECRET_KEY.

    Fernet requires a 32-byte base64-encoded key.
    """
    # Use SHA256 to derive a consistent 32-byte key from SECRET_KEY
    key_bytes = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes)


def _get_fernet() -> Fernet:
    """Get Fernet instance for encryption/decryption."""
    return Fernet(_get_encryption_key())


def encrypt_secret(plaintext: str) -> str:
    """
    Encrypt a secret string.

    Args:
        plaintext: The secret to encrypt

    Returns:
        Base64-encoded encrypted string
    """
    if not plaintext:
        return ""

    fernet = _get_fernet()
    encrypted = fernet.encrypt(plaintext.encode())
    return encrypted.decode()


def decrypt_secret(ciphertext: str) -> str:
    """
    Decrypt an encrypted secret.

    Args:
        ciphertext: The encrypted string

    Returns:
        Decrypted plaintext

    Raises:
        cryptography.fernet.InvalidToken: If decryption fails
    """
    if not ciphertext:
        return ""

    fernet = _get_fernet()
    decrypted = fernet.decrypt(ciphertext.encode())
    return decrypted.decode()


def mask_secret(secret: Optional[str], show_chars: int = 4) -> str:
    """
    Mask a secret for display (e.g., "abc...xyz").

    Args:
        secret: The secret to mask
        show_chars: Number of characters to show at start/end

    Returns:
        Masked string or empty string if secret is None/empty
    """
    if not secret:
        return ""

    if len(secret) <= show_chars * 2:
        return "*" * len(secret)

    return f"{secret[:show_chars]}...{secret[-show_chars:]}"
