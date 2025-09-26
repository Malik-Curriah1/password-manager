"""
Crypto module for the Offline Password Manager.

This module provides all cryptographic primitives including:
- Key derivation using Argon2id and PBKDF2
- AES-256-GCM encryption/decryption
- Secure random generation
- Key wrapping and unwrapping
"""

import os
import json
import secrets
from typing import NamedTuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import hash_password_raw, Type
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


class KDFParams(NamedTuple):
    """Key Derivation Function parameters."""
    algorithm: str  # "argon2id" or "pbkdf2"
    salt: bytes
    iterations: int  # For PBKDF2
    memory_cost: int  # For Argon2
    parallelism: int  # For Argon2
    hash_length: int


class EncryptionResult(NamedTuple):
    """Result of encryption operation."""
    ciphertext: bytes
    nonce: bytes
    tag: bytes


class CryptoError(Exception):
    """Raised when cryptographic operations fail."""
    pass


class AuthenticationError(CryptoError):
    """Raised when authentication fails during decryption."""
    pass


class ValidationError(CryptoError):
    """Raised when input validation fails."""
    pass


# Security Parameters
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_ITERATIONS = 3
ARGON2_HASH_LENGTH = 32

PBKDF2_ITERATIONS = 100000
PBKDF2_HASH_LENGTH = 32

AES_KEY_LENGTH = 32  # 256 bits
AES_NONCE_LENGTH = 12  # 96 bits for GCM
SALT_LENGTH = 32


def generate_salt(length: int = SALT_LENGTH) -> bytes:
    """Generate cryptographically secure random salt."""
    try:
        return os.urandom(length)
    except Exception as e:
        raise CryptoError(f"Failed to generate salt: {e}")


def generate_nonce(length: int = AES_NONCE_LENGTH) -> bytes:
    """Generate cryptographically secure random nonce."""
    try:
        return os.urandom(length)
    except Exception as e:
        raise CryptoError(f"Failed to generate nonce: {e}")


def generate_vault_key(length: int = AES_KEY_LENGTH) -> bytes:
    """Generate random vault key."""
    try:
        return os.urandom(length)
    except Exception as e:
        raise CryptoError(f"Failed to generate vault key: {e}")


def create_kdf_params(algorithm: str = "argon2id") -> KDFParams:
    """Create KDF parameters for key derivation."""
    try:
        salt = generate_salt()
        
        if algorithm == "argon2id":
            return KDFParams(
                algorithm="argon2id",
                salt=salt,
                iterations=ARGON2_ITERATIONS,  # Use proper iterations for Argon2
                memory_cost=ARGON2_MEMORY_COST,
                parallelism=ARGON2_PARALLELISM,
                hash_length=ARGON2_HASH_LENGTH
            )
        elif algorithm == "pbkdf2":
            return KDFParams(
                algorithm="pbkdf2",
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
                memory_cost=0,  # Not used for PBKDF2
                parallelism=0,  # Not used for PBKDF2
                hash_length=PBKDF2_HASH_LENGTH
            )
        else:
            raise ValidationError(f"Unsupported KDF algorithm: {algorithm}")
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError)):
            raise
        raise CryptoError(f"Failed to create KDF parameters: {e}")


def derive_master_key(password: str, salt: bytes, params: KDFParams) -> bytes:
    """Derive master key from password using KDF."""
    try:
        if not password:
            raise ValidationError("Password cannot be empty")
        
        password_bytes = password.encode('utf-8')
        
        if params.algorithm == "argon2id":
            return hash_password_raw(
                password=password_bytes,
                salt=salt,
                time_cost=max(params.iterations, 1),  # Ensure at least 1
                memory_cost=params.memory_cost,
                parallelism=params.parallelism,
                hash_len=params.hash_length,
                type=Type.ID  # Argon2id
            )
        
        elif params.algorithm == "pbkdf2":
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=params.hash_length,
                salt=salt,
                iterations=params.iterations
            )
            return kdf.derive(password_bytes)
        
        else:
            raise ValidationError(f"Unsupported KDF algorithm: {params.algorithm}")
    
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError)):
            raise
        raise CryptoError(f"Failed to derive master key: {e}")


def wrap_vault_key(master_key: bytes, vault_key: bytes) -> EncryptionResult:
    """Encrypt vault key with master key."""
    try:
        if len(master_key) != AES_KEY_LENGTH:
            raise ValidationError(f"Master key must be {AES_KEY_LENGTH} bytes")
        if len(vault_key) != AES_KEY_LENGTH:
            raise ValidationError(f"Vault key must be {AES_KEY_LENGTH} bytes")
        
        nonce = generate_nonce()
        aesgcm = AESGCM(master_key)
        ciphertext = aesgcm.encrypt(nonce, vault_key, None)
        
        # Split ciphertext and tag
        tag = ciphertext[-16:]  # Last 16 bytes are the tag
        ciphertext_only = ciphertext[:-16]
        
        return EncryptionResult(
            ciphertext=ciphertext_only,
            nonce=nonce,
            tag=tag
        )
    
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError)):
            raise
        raise CryptoError(f"Failed to wrap vault key: {e}")


def unwrap_vault_key(master_key: bytes, wrapped_data: EncryptionResult) -> bytes:
    """Decrypt vault key using master key."""
    try:
        if len(master_key) != AES_KEY_LENGTH:
            raise ValidationError(f"Master key must be {AES_KEY_LENGTH} bytes")
        
        # Reconstruct ciphertext with tag
        ciphertext = wrapped_data.ciphertext + wrapped_data.tag
        
        aesgcm = AESGCM(master_key)
        vault_key = aesgcm.decrypt(wrapped_data.nonce, ciphertext, None)
        
        return vault_key
    
    except InvalidTag:
        raise AuthenticationError("Failed to decrypt vault key - invalid authentication tag")
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, AuthenticationError)):
            raise
        raise CryptoError(f"Failed to unwrap vault key: {e}")


def encrypt_entry(vault_key: bytes, entry_data: dict) -> EncryptionResult:
    """Encrypt password entry with vault key."""
    try:
        if len(vault_key) != AES_KEY_LENGTH:
            raise ValidationError(f"Vault key must be {AES_KEY_LENGTH} bytes")
        
        # Serialize entry to JSON
        plaintext = json.dumps(entry_data, sort_keys=True).encode('utf-8')
        
        nonce = generate_nonce()
        aesgcm = AESGCM(vault_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Split ciphertext and tag
        tag = ciphertext[-16:]  # Last 16 bytes are the tag
        ciphertext_only = ciphertext[:-16]
        
        return EncryptionResult(
            ciphertext=ciphertext_only,
            nonce=nonce,
            tag=tag
        )
    
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError)):
            raise
        raise CryptoError(f"Failed to encrypt entry: {e}")


def decrypt_entry(vault_key: bytes, encrypted_data: EncryptionResult) -> dict:
    """Decrypt password entry using vault key."""
    try:
        if len(vault_key) != AES_KEY_LENGTH:
            raise ValidationError(f"Vault key must be {AES_KEY_LENGTH} bytes")
        
        # Reconstruct ciphertext with tag
        ciphertext = encrypted_data.ciphertext + encrypted_data.tag
        
        aesgcm = AESGCM(vault_key)
        plaintext = aesgcm.decrypt(encrypted_data.nonce, ciphertext, None)
        
        # Deserialize JSON
        entry_data = json.loads(plaintext.decode('utf-8'))
        return entry_data
    
    except InvalidTag:
        raise AuthenticationError("Failed to decrypt entry - invalid authentication tag")
    except json.JSONDecodeError as e:
        raise ValidationError(f"Failed to deserialize decrypted data: {e}")
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, AuthenticationError)):
            raise
        raise CryptoError(f"Failed to decrypt entry: {e}")


def encrypt_field(vault_key: bytes, plaintext: str) -> EncryptionResult:
    """Encrypt a single field (e.g., title for search)."""
    try:
        if len(vault_key) != AES_KEY_LENGTH:
            raise ValidationError(f"Vault key must be {AES_KEY_LENGTH} bytes")
        
        plaintext_bytes = plaintext.encode('utf-8')
        nonce = generate_nonce()
        aesgcm = AESGCM(vault_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
        
        # Split ciphertext and tag
        tag = ciphertext[-16:]  # Last 16 bytes are the tag
        ciphertext_only = ciphertext[:-16]
        
        return EncryptionResult(
            ciphertext=ciphertext_only,
            nonce=nonce,
            tag=tag
        )
    
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError)):
            raise
        raise CryptoError(f"Failed to encrypt field: {e}")


def decrypt_field(vault_key: bytes, encrypted_data: EncryptionResult) -> str:
    """Decrypt a single field."""
    try:
        if len(vault_key) != AES_KEY_LENGTH:
            raise ValidationError(f"Vault key must be {AES_KEY_LENGTH} bytes")
        
        # Reconstruct ciphertext with tag
        ciphertext = encrypted_data.ciphertext + encrypted_data.tag
        
        aesgcm = AESGCM(vault_key)
        plaintext = aesgcm.decrypt(encrypted_data.nonce, ciphertext, None)
        
        return plaintext.decode('utf-8')
    
    except InvalidTag:
        raise AuthenticationError("Failed to decrypt field - invalid authentication tag")
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, AuthenticationError)):
            raise
        raise CryptoError(f"Failed to decrypt field: {e}")


def secure_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    return secrets.compare_digest(a, b)


def clear_sensitive_data(data: bytes) -> None:
    """Securely clear sensitive data from memory."""
    try:
        # Overwrite with random data
        for i in range(len(data)):
            data[i:i+1] = os.urandom(1)
    except Exception:
        # If we can't clear the data, at least try to overwrite it
        try:
            data[:] = b'\x00' * len(data)
        except Exception:
            pass  # Best effort


def generate_backup_key() -> bytes:
    """Generate key for encrypted backup."""
    try:
        return os.urandom(AES_KEY_LENGTH)
    except Exception as e:
        raise CryptoError(f"Failed to generate backup key: {e}")


def encrypt_backup(data: bytes, key: bytes) -> EncryptionResult:
    """Encrypt backup data."""
    try:
        if len(key) != AES_KEY_LENGTH:
            raise ValidationError(f"Backup key must be {AES_KEY_LENGTH} bytes")
        
        nonce = generate_nonce()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Split ciphertext and tag
        tag = ciphertext[-16:]  # Last 16 bytes are the tag
        ciphertext_only = ciphertext[:-16]
        
        return EncryptionResult(
            ciphertext=ciphertext_only,
            nonce=nonce,
            tag=tag
        )
    
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError)):
            raise
        raise CryptoError(f"Failed to encrypt backup: {e}")


def decrypt_backup(encrypted_data: EncryptionResult, key: bytes) -> bytes:
    """Decrypt backup data."""
    try:
        if len(key) != AES_KEY_LENGTH:
            raise ValidationError(f"Backup key must be {AES_KEY_LENGTH} bytes")
        
        # Reconstruct ciphertext with tag
        ciphertext = encrypted_data.ciphertext + encrypted_data.tag
        
        aesgcm = AESGCM(key)
        data = aesgcm.decrypt(encrypted_data.nonce, ciphertext, None)
        
        return data
    
    except InvalidTag:
        raise AuthenticationError("Failed to decrypt backup - invalid authentication tag")
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, AuthenticationError)):
            raise
        raise CryptoError(f"Failed to decrypt backup: {e}")


def derive_backup_key(master_password: str, salt: bytes) -> bytes:
    """Derive backup key from master password."""
    try:
        if not master_password:
            raise ValidationError("Master password cannot be empty")
        
        password_bytes = master_password.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS
        )
        
        return kdf.derive(password_bytes)
    
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError)):
            raise
        raise CryptoError(f"Failed to derive backup key: {e}")
