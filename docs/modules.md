# Offline Password Manager — Modules & Interfaces

This document describes the **public API** of each module in the password manager.  
Functions are shown in pseudocode signatures, not final implementations.

---

## 1. CLI Layer (`cli.py`)

### Responsibilities
- Parse commands and arguments.
- Prompt user for master password.
- Call `vault.py` functions.
- Handle user input validation and error display.

### Functions
```python
def main():
    """Entry point — dispatch commands from sys.argv."""
    # Parses command line arguments and calls appropriate command function
    # Returns: None
    # Raises: SystemExit on invalid arguments

def cmd_init():
    """Initialize a new vault."""
    # Prompts for master password (twice for confirmation)
    # Calls vault.init_vault()
    # Returns: None
    # Raises: VaultError, KeyboardInterrupt

def cmd_open():
    """Unlock vault for current session."""
    # Prompts for master password
    # Calls vault.open_vault()
    # Returns: None
    # Raises: VaultError, KeyboardInterrupt

def cmd_add():
    """Add a new password entry."""
    # Prompts for entry details (title, username, password, URL, notes)
    # Calls vault.add_entry()
    # Returns: None
    # Raises: VaultError, ValidationError

def cmd_get(entry_id: str):
    """Retrieve and show a password entry."""
    # Calls vault.get_entry()
    # Displays entry details (with option to copy password)
    # Returns: None
    # Raises: VaultError, EntryNotFoundError

def cmd_list():
    """List available entries (titles only)."""
    # Calls vault.list_entries()
    # Displays formatted list
    # Returns: None
    # Raises: VaultError

def cmd_update(entry_id: str):
    """Update an existing entry."""
    # Prompts for updated fields
    # Calls vault.update_entry()
    # Returns: None
    # Raises: VaultError, EntryNotFoundError, ValidationError

def cmd_delete(entry_id: str):
    """Delete an entry."""
    # Confirms deletion with user
    # Calls vault.delete_entry()
    # Returns: None
    # Raises: VaultError, EntryNotFoundError

def cmd_rekey():
    """Change master password (re-encrypt vault key)."""
    # Prompts for current and new master passwords
    # Calls vault.rekey_vault()
    # Returns: None
    # Raises: VaultError, KeyboardInterrupt

def cmd_export(filepath: str):
    """Export encrypted backup."""
    # Calls vault.export_vault()
    # Saves backup to specified file
    # Returns: None
    # Raises: VaultError, IOError

def cmd_import(filepath: str):
    """Import encrypted backup."""
    # Loads backup from specified file
    # Calls vault.import_vault()
    # Returns: None
    # Raises: VaultError, IOError, ValidationError

def get_master_password(prompt: str = "Master password: ") -> str:
    """Securely prompt for master password."""
    # Uses getpass.getpass() for secure input
    # Returns: str (master password)
    # Raises: KeyboardInterrupt

def confirm_master_password() -> str:
    """Prompt for master password with confirmation."""
    # Prompts twice and verifies they match
    # Returns: str (confirmed master password)
    # Raises: ValidationError, KeyboardInterrupt
```

---

## 2. Vault API Layer (`vault.py`)

### Responsibilities
- Orchestrate all vault operations.
- Mediate between DB and Crypto layers.
- Enforce encryption boundaries.
- Manage vault state and session.

### Data Structures
```python
from typing import Dict, List, Optional, NamedTuple
from dataclasses import dataclass

@dataclass
class VaultConfig:
    """Vault configuration parameters."""
    version: str
    kdf: str
    kdf_salt: bytes
    kdf_params: Dict[str, any]
    encrypted_vault_key: bytes
    created_at: str
    modified_at: str

@dataclass
class Entry:
    """Password entry data structure."""
    entry_id: str
    title: str
    username: str
    password: str
    url: str
    notes: str
    created_at: str
    updated_at: str

@dataclass
class EncryptedEntry:
    """Encrypted entry data structure."""
    entry_id: str
    title_cipher: bytes
    username_cipher: bytes
    password_cipher: bytes
    notes_cipher: bytes
    url_cipher: bytes
    nonce: bytes
    tag: bytes
    created_at: str
    updated_at: str
```

### Functions
```python
def init_vault(master_password: str, vault_path: str = "vault.db") -> None:
    """Initialize a new vault with master password."""
    # Derives master key using crypto.derive_master_key()
    # Generates random vault key
    # Encrypts vault key with master key
    # Creates database schema
    # Stores vault metadata
    # Returns: None
    # Raises: VaultError, DatabaseError

def open_vault(master_password: str, vault_path: str = "vault.db") -> None:
    """Unlock vault by decrypting vault key."""
    # Derives master key from password
    # Loads vault metadata from database
    # Decrypts vault key using master key
    # Stores vault key in memory for session
    # Returns: None
    # Raises: VaultError, AuthenticationError, DatabaseError

def close_vault() -> None:
    """Close vault and clear sensitive data from memory."""
    # Clears vault key from memory
    # Closes database connection
    # Returns: None

def is_vault_open() -> bool:
    """Check if vault is currently open."""
    # Returns: bool (True if vault is unlocked)

def add_entry(title: str, username: str, password: str, 
             url: str = "", notes: str = "") -> str:
    """Add a new password entry."""
    # Validates input parameters
    # Creates Entry object
    # Encrypts entry using crypto.encrypt_entry()
    # Stores encrypted entry in database
    # Returns: str (entry_id)
    # Raises: VaultError, ValidationError, DatabaseError

def get_entry(entry_id: str) -> Entry:
    """Retrieve and decrypt a password entry."""
    # Fetches encrypted entry from database
    # Decrypts entry using crypto.decrypt_entry()
    # Returns: Entry object
    # Raises: VaultError, EntryNotFoundError, DatabaseError

def list_entries() -> List[Dict[str, str]]:
    """List all entries (titles and IDs only)."""
    # Fetches entry metadata from database
    # Decrypts only titles for display
    # Returns: List[Dict] with entry_id and title
    # Raises: VaultError, DatabaseError

def update_entry(entry_id: str, **kwargs) -> None:
    """Update an existing entry."""
    # Validates entry_id exists
    # Updates specified fields
    # Re-encrypts entire entry
    # Updates database
    # Returns: None
    # Raises: VaultError, EntryNotFoundError, ValidationError, DatabaseError

def delete_entry(entry_id: str) -> None:
    """Delete a password entry."""
    # Validates entry_id exists
    # Removes entry from database
    # Returns: None
    # Raises: VaultError, EntryNotFoundError, DatabaseError

def search_entries(query: str) -> List[Dict[str, str]]:
    """Search entries by title (case-insensitive)."""
    # Searches through decrypted titles
    # Returns: List[Dict] with matching entries
    # Raises: VaultError, DatabaseError

def rekey_vault(new_master_password: str) -> None:
    """Change master password and re-encrypt vault key."""
    # Derives new master key
    # Re-encrypts vault key with new master key
    # Updates vault metadata
    # Returns: None
    # Raises: VaultError, DatabaseError

def export_vault() -> bytes:
    """Export vault as encrypted backup."""
    # Retrieves all encrypted entries
    # Creates encrypted backup format
    # Returns: bytes (encrypted backup data)
    # Raises: VaultError, DatabaseError

def import_vault(backup_data: bytes) -> None:
    """Import entries from encrypted backup."""
    # Decrypts backup data
    # Validates backup format
    # Imports entries into current vault
    # Returns: None
    # Raises: VaultError, ValidationError, DatabaseError

def get_vault_info() -> Dict[str, any]:
    """Get vault metadata and statistics."""
    # Returns vault configuration and entry count
    # Returns: Dict with vault info
    # Raises: VaultError, DatabaseError

def change_master_password(old_password: str, new_password: str) -> None:
    """Change master password with old password verification."""
    # Verifies old password
    # Calls rekey_vault() with new password
    # Returns: None
    # Raises: VaultError, AuthenticationError, DatabaseError
```

---

## 3. Database Layer (`db.py`)

### Responsibilities
- Handle SQLite persistence.
- Store only ciphertext and metadata.
- Provide CRUD operations for entries and vault metadata.
- Manage database schema and migrations.

### Functions
```python
def init_database(db_path: str) -> None:
    """Initialize database with schema."""
    # Creates database file if it doesn't exist
    # Creates vault_meta and entries tables
    # Returns: None
    # Raises: DatabaseError

def create_vault_meta(config: VaultConfig) -> None:
    """Store vault metadata."""
    # Inserts vault configuration into vault_meta table
    # Returns: None
    # Raises: DatabaseError

def get_vault_meta() -> VaultConfig:
    """Retrieve vault metadata."""
    # Fetches vault configuration from vault_meta table
    # Returns: VaultConfig object
    # Raises: DatabaseError, VaultNotFoundError

def update_vault_meta(config: VaultConfig) -> None:
    """Update vault metadata."""
    # Updates vault configuration in vault_meta table
    # Returns: None
    # Raises: DatabaseError

def insert_entry(encrypted_entry: EncryptedEntry) -> None:
    """Insert encrypted entry into database."""
    # Stores encrypted entry data in entries table
    # Returns: None
    # Raises: DatabaseError

def get_entry(entry_id: str) -> EncryptedEntry:
    """Retrieve encrypted entry by ID."""
    # Fetches encrypted entry from entries table
    # Returns: EncryptedEntry object
    # Raises: DatabaseError, EntryNotFoundError

def get_all_entries() -> List[EncryptedEntry]:
    """Retrieve all encrypted entries."""
    # Fetches all entries from entries table
    # Returns: List[EncryptedEntry]
    # Raises: DatabaseError

def get_entry_titles() -> List[Dict[str, str]]:
    """Get entry IDs and encrypted titles for listing."""
    # Fetches entry_id and title_cipher from entries table
    # Returns: List[Dict] with entry_id and title_cipher
    # Raises: DatabaseError

def update_entry(entry_id: str, encrypted_entry: EncryptedEntry) -> None:
    """Update encrypted entry in database."""
    # Updates entry data in entries table
    # Returns: None
    # Raises: DatabaseError, EntryNotFoundError

def delete_entry(entry_id: str) -> None:
    """Delete entry from database."""
    # Removes entry from entries table
    # Returns: None
    # Raises: DatabaseError, EntryNotFoundError

def entry_exists(entry_id: str) -> bool:
    """Check if entry exists in database."""
    # Queries entries table for entry_id
    # Returns: bool
    # Raises: DatabaseError

def get_entry_count() -> int:
    """Get total number of entries."""
    # Counts entries in entries table
    # Returns: int
    # Raises: DatabaseError

def close_connection() -> None:
    """Close database connection."""
    # Closes SQLite connection
    # Returns: None

def backup_database(source_path: str, backup_path: str) -> None:
    """Create backup of database file."""
    # Copies database file to backup location
    # Returns: None
    # Raises: IOError, DatabaseError

def restore_database(backup_path: str, target_path: str) -> None:
    """Restore database from backup."""
    # Copies backup file to target location
    # Returns: None
    # Raises: IOError, DatabaseError

def get_database_info() -> Dict[str, any]:
    """Get database statistics and information."""
    # Returns database file size, entry count, etc.
    # Returns: Dict with database info
    # Raises: DatabaseError
```

---

## 4. Crypto Layer (`crypto.py`)

### Responsibilities
- Implement all cryptographic primitives.
- Derive master keys using KDF.
- Encrypt/decrypt vault keys and entries.
- Generate secure random values.

### Data Structures
```python
from typing import NamedTuple

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
```

### Functions
```python
def generate_salt(length: int = 32) -> bytes:
    """Generate cryptographically secure random salt."""
    # Uses os.urandom() or secrets.token_bytes()
    # Returns: bytes (random salt)
    # Raises: CryptoError

def generate_nonce(length: int = 12) -> bytes:
    """Generate cryptographically secure random nonce."""
    # Uses os.urandom() for AES-GCM nonce
    # Returns: bytes (random nonce)
    # Raises: CryptoError

def generate_vault_key(length: int = 32) -> bytes:
    """Generate random vault key."""
    # Uses os.urandom() for AES-256 key
    # Returns: bytes (random vault key)
    # Raises: CryptoError

def derive_master_key(password: str, salt: bytes, 
                     params: KDFParams) -> bytes:
    """Derive master key from password using KDF."""
    # Uses Argon2id (preferred) or PBKDF2 (fallback)
    # Returns: bytes (derived master key)
    # Raises: CryptoError, ValidationError

def create_kdf_params(algorithm: str = "argon2id") -> KDFParams:
    """Create KDF parameters for key derivation."""
    # Generates salt and sets appropriate parameters
    # Returns: KDFParams object
    # Raises: CryptoError, ValidationError

def wrap_vault_key(master_key: bytes, vault_key: bytes) -> EncryptionResult:
    """Encrypt vault key with master key."""
    # Uses AES-256-GCM encryption
    # Generates fresh nonce
    # Returns: EncryptionResult
    # Raises: CryptoError

def unwrap_vault_key(master_key: bytes, wrapped_data: EncryptionResult) -> bytes:
    """Decrypt vault key using master key."""
    # Uses AES-256-GCM decryption
    # Verifies authentication tag
    # Returns: bytes (decrypted vault key)
    # Raises: CryptoError, AuthenticationError

def encrypt_entry(vault_key: bytes, entry: Entry) -> EncryptionResult:
    """Encrypt password entry with vault key."""
    # Serializes entry to JSON
    # Encrypts with AES-256-GCM
    # Generates fresh nonce
    # Returns: EncryptionResult
    # Raises: CryptoError, ValidationError

def decrypt_entry(vault_key: bytes, encrypted_data: EncryptionResult) -> Entry:
    """Decrypt password entry using vault key."""
    # Decrypts with AES-256-GCM
    # Verifies authentication tag
    # Deserializes JSON to Entry object
    # Returns: Entry object
    # Raises: CryptoError, AuthenticationError, ValidationError

def encrypt_field(vault_key: bytes, plaintext: str) -> EncryptionResult:
    """Encrypt a single field (e.g., title for search)."""
    # Encrypts individual field with AES-256-GCM
    # Returns: EncryptionResult
    # Raises: CryptoError

def decrypt_field(vault_key: bytes, encrypted_data: EncryptionResult) -> str:
    """Decrypt a single field."""
    # Decrypts individual field with AES-256-GCM
    # Returns: str (decrypted field)
    # Raises: CryptoError, AuthenticationError

def secure_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    # Uses secrets.compare_digest()
    # Returns: bool
    # Raises: None

def clear_sensitive_data(data: bytes) -> None:
    """Securely clear sensitive data from memory."""
    # Overwrites memory with random data
    # Returns: None

def generate_backup_key() -> bytes:
    """Generate key for encrypted backup."""
    # Uses os.urandom() for backup encryption
    # Returns: bytes (backup key)
    # Raises: CryptoError

def encrypt_backup(data: bytes, key: bytes) -> EncryptionResult:
    """Encrypt backup data."""
    # Encrypts backup with AES-256-GCM
    # Returns: EncryptionResult
    # Raises: CryptoError

def decrypt_backup(encrypted_data: EncryptionResult, key: bytes) -> bytes:
    """Decrypt backup data."""
    # Decrypts backup with AES-256-GCM
    # Returns: bytes (decrypted backup)
    # Raises: CryptoError, AuthenticationError

def derive_backup_key(master_password: str, salt: bytes) -> bytes:
    """Derive backup key from master password."""
    # Uses PBKDF2 for backup key derivation
    # Returns: bytes (backup key)
    # Raises: CryptoError
```

---

## 5. Exception Classes

### Custom Exceptions
```python
class VaultError(Exception):
    """Base exception for vault operations."""
    pass

class AuthenticationError(VaultError):
    """Raised when authentication fails."""
    pass

class VaultNotFoundError(VaultError):
    """Raised when vault file doesn't exist."""
    pass

class EntryNotFoundError(VaultError):
    """Raised when entry doesn't exist."""
    pass

class ValidationError(VaultError):
    """Raised when input validation fails."""
    pass

class DatabaseError(VaultError):
    """Raised when database operations fail."""
    pass

class CryptoError(VaultError):
    """Raised when cryptographic operations fail."""
    pass

class BackupError(VaultError):
    """Raised when backup/restore operations fail."""
    pass
```

---

## 6. Configuration Constants

### Security Parameters
```python
# KDF Parameters
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_ITERATIONS = 3
ARGON2_HASH_LENGTH = 32

PBKDF2_ITERATIONS = 100000
PBKDF2_HASH_LENGTH = 32

# Encryption Parameters
AES_KEY_LENGTH = 32  # 256 bits
AES_NONCE_LENGTH = 12  # 96 bits for GCM
SALT_LENGTH = 32

# Vault Parameters
VAULT_VERSION = "1.0"
AUTO_LOCK_TIMEOUT = 300  # 5 minutes in seconds
MAX_PASSWORD_LENGTH = 1024
MAX_ENTRY_LENGTH = 10000
```

---

## 7. Module Dependencies

### Import Structure
```python
# cli.py imports
from vault import VaultError, AuthenticationError, EntryNotFoundError
from getpass import getpass
import sys
import argparse

# vault.py imports
from db import init_database, create_vault_meta, get_vault_meta, insert_entry, get_entry, update_entry, delete_entry, get_all_entries, get_entry_titles
from crypto import derive_master_key, wrap_vault_key, unwrap_vault_key, encrypt_entry, decrypt_entry, create_kdf_params, generate_vault_key
import uuid
from datetime import datetime

# db.py imports
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Optional

# crypto.py imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets
import os
import json
```

This completes the comprehensive API specification for all modules in the password manager system.
