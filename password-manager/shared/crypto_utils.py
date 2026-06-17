# -*- coding: utf-8 -*-
"""
密码管理器 - 加密工具模块 (Web版)
"""

import os
import base64
import secrets
import string

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def generate_salt() -> bytes:
    return os.urandom(16)


def create_cipher(key: bytes) -> Fernet:
    return Fernet(key)


def encrypt(cipher: Fernet, plaintext: str) -> str:
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt(cipher: Fernet, ciphertext: str) -> str:
    return cipher.decrypt(ciphertext.encode()).decode()


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def check_password_strength(password: str) -> tuple:
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.islower() for c in password) and any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;:',.<>?/`~" for c in password):
        score += 1
    labels = {0: "非常弱", 1: "弱", 2: "一般", 3: "强", 4: "非常强", 5: "极强"}
    score = min(score, 5)
    return score, labels[score]
