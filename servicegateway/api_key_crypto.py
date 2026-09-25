"""Reversible encryption for admin-visible API keys.

Authentication continues to use token_hash.  The ciphertext is only for the
authenticated management UI so administrators can view/copy a key later.
"""
import base64
import hashlib
import re
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOKEN_RE = re.compile(r'^sg_[A-Za-z0-9_-]{20,180}$')


class ApiKeyCipherError(ValueError):
    pass


def _key(auth_secret: str) -> bytes:
    if not isinstance(auth_secret, str) or len(auth_secret) < 32:
        raise ApiKeyCipherError('Invalid API key encryption secret')
    return hashlib.sha256(b'servicegateway-api-key-v1\0' + auth_secret.encode()).digest()


def encrypt_token(token: str, key_id: str, auth_secret: str) -> str:
    if not TOKEN_RE.fullmatch(token or ''):
        raise ApiKeyCipherError('Invalid API key token')
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_key(auth_secret)).encrypt(nonce, token.encode(), key_id.encode())
    return base64.urlsafe_b64encode(nonce + ciphertext).decode().rstrip('=')


def decrypt_token(value: str, key_id: str, auth_secret: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ApiKeyCipherError('Invalid API key ciphertext')
    try:
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
        if len(raw) < 29:
            raise ValueError
        token = AESGCM(_key(auth_secret)).decrypt(raw[:12], raw[12:], key_id.encode()).decode()
    except Exception:
        raise ApiKeyCipherError('API key ciphertext cannot be decrypted') from None
    if not TOKEN_RE.fullmatch(token):
        raise ApiKeyCipherError('Decrypted API key token is invalid')
    return token
