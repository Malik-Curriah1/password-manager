"""
Vault module for the Offline Password Manager.

This module orchestrates all vault operations and mediates between
the database and crypto layers.
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass

from src.crypto import (
    derive_master_key, wrap_vault_key, unwrap_vault_key, encrypt_entry, decrypt_entry,
    create_kdf_params, generate_vault_key, encrypt_field, decrypt_field,
    generate_backup_key, encrypt_backup, decrypt_backup, derive_backup_key,
    EncryptionResult, KDFParams, CryptoError, AuthenticationError, ValidationError
)
from src.db import (
    init_database, create_vault_meta, get_vault_meta, update_vault_meta,
    insert_entry, get_entry, update_entry, delete_entry, get_all_entries,
    get_entry_titles, entry_exists, get_entry_count, get_database_info,
    VaultConfig, EncryptedEntry, DatabaseError, VaultNotFoundError, EntryNotFoundError
)


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


class VaultError(Exception):
    """Base exception for vault operations."""
    pass


class VaultManager:
    """Manages vault state and operations."""
    
    def __init__(self):
        self.vault_key: Optional[bytes] = None
        self.vault_path: Optional[str] = None
        self.is_open = False
    
    def _ensure_vault_open(self) -> None:
        """Ensure vault is open before operations."""
        if not self.is_open or not self.vault_key:
            raise VaultError("Vault is not open. Use open_vault() first.")
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp as ISO string."""
        return datetime.now().isoformat()


def init_vault(master_password: str, vault_path: str = "vault.db") -> None:
    """Initialize a new vault with master password."""
    try:
        if not master_password:
            raise ValidationError("Master password cannot be empty")
        
        # Create KDF parameters
        kdf_params = create_kdf_params("argon2id")
        
        # Derive master key
        master_key = derive_master_key(master_password, kdf_params.salt, kdf_params)
        
        # Generate vault key
        vault_key = generate_vault_key()
        
        # Encrypt vault key with master key
        wrapped_vault_key = wrap_vault_key(master_key, vault_key)
        
        # Create vault configuration
        timestamp = datetime.now().isoformat()
        config = VaultConfig(
            version="1.0",
            kdf="argon2id",
            kdf_salt=kdf_params.salt,
            kdf_params={
                "memory_cost": kdf_params.memory_cost,
                "parallelism": kdf_params.parallelism,
                "iterations": kdf_params.iterations,
                "hash_length": kdf_params.hash_length
            },
            encrypted_vault_key=wrapped_vault_key.ciphertext,
            vault_key_nonce=wrapped_vault_key.nonce,
            vault_key_tag=wrapped_vault_key.tag,
            created_at=timestamp,
            modified_at=timestamp
        )
        
        # Initialize database and store metadata
        init_database(vault_path)
        create_vault_meta(vault_path, config)
        
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, DatabaseError)):
            raise VaultError(f"Failed to initialize vault: {e}")
        raise VaultError(f"Unexpected error initializing vault: {e}")


def open_vault(master_password: str, vault_path: str = "vault.db") -> None:
    """Unlock vault by decrypting vault key."""
    try:
        if not master_password:
            raise ValidationError("Master password cannot be empty")
        
        # Load vault metadata
        config = get_vault_meta(vault_path)
        
        # Create KDF parameters from stored config
        kdf_params = KDFParams(
            algorithm=config.kdf,
            salt=config.kdf_salt,
            iterations=config.kdf_params.get("iterations", 0),
            memory_cost=config.kdf_params.get("memory_cost", 0),
            parallelism=config.kdf_params.get("parallelism", 0),
            hash_length=config.kdf_params.get("hash_length", 32)
        )
        
        # Derive master key
        master_key = derive_master_key(master_password, kdf_params.salt, kdf_params)
        
        # Decrypt vault key
        wrapped_data = EncryptionResult(
            ciphertext=config.encrypted_vault_key,
            nonce=config.vault_key_nonce,
            tag=config.vault_key_tag
        )
        
        vault_key = unwrap_vault_key(master_key, wrapped_data)
        
        # Store vault state
        vault_manager.vault_key = vault_key
        vault_manager.vault_path = vault_path
        vault_manager.is_open = True
        
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, DatabaseError, VaultNotFoundError)):
            raise VaultError(f"Failed to open vault: {e}")
        raise VaultError(f"Unexpected error opening vault: {e}")


def close_vault() -> None:
    """Close vault and clear sensitive data from memory."""
    try:
        if vault_manager.vault_key:
            vault_manager.vault_key = None
        vault_manager.vault_path = None
        vault_manager.is_open = False
    except Exception as e:
        raise VaultError(f"Failed to close vault: {e}")


def is_vault_open() -> bool:
    """Check if vault is currently open."""
    return vault_manager.is_open


def add_entry(title: str, username: str, password: str, 
             url: str = "", notes: str = "") -> str:
    """Add a new password entry."""
    try:
        vault_manager._ensure_vault_open()
        if not title or not username or not password:
            raise ValidationError("Title, username, and password are required")
        entry_id = str(uuid.uuid4())
        timestamp = vault_manager._get_current_timestamp()
        # Encrypt each field separately
        title_enc = encrypt_field(vault_manager.vault_key, title)
        username_enc = encrypt_field(vault_manager.vault_key, username)
        password_enc = encrypt_field(vault_manager.vault_key, password)
        notes_enc = encrypt_field(vault_manager.vault_key, notes)
        url_enc = encrypt_field(vault_manager.vault_key, url)
        encrypted_entry = EncryptedEntry(
            entry_id=entry_id,
            title_cipher=title_enc.ciphertext,
            title_nonce=title_enc.nonce,
            title_tag=title_enc.tag,
            username_cipher=username_enc.ciphertext,
            username_nonce=username_enc.nonce,
            username_tag=username_enc.tag,
            password_cipher=password_enc.ciphertext,
            password_nonce=password_enc.nonce,
            password_tag=password_enc.tag,
            notes_cipher=notes_enc.ciphertext,
            notes_nonce=notes_enc.nonce,
            notes_tag=notes_enc.tag,
            url_cipher=url_enc.ciphertext,
            url_nonce=url_enc.nonce,
            url_tag=url_enc.tag,
            created_at=timestamp,
            updated_at=timestamp
        )
        from src.db import insert_entry as db_insert_entry
        db_insert_entry(vault_manager.vault_path, encrypted_entry)
        return entry_id
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, DatabaseError, VaultError)):
            raise
        raise VaultError(f"Unexpected error adding entry: {e}")


def get_entry(entry_id: str) -> Entry:
    """Retrieve and decrypt a password entry."""
    try:
        vault_manager._ensure_vault_open()
        from src.db import get_entry as db_get_entry
        encrypted_entry = db_get_entry(vault_manager.vault_path, entry_id)
        # Decrypt each field
        title = decrypt_field(vault_manager.vault_key, EncryptionResult(
            ciphertext=encrypted_entry.title_cipher,
            nonce=encrypted_entry.title_nonce,
            tag=encrypted_entry.title_tag
        ))
        username = decrypt_field(vault_manager.vault_key, EncryptionResult(
            ciphertext=encrypted_entry.username_cipher,
            nonce=encrypted_entry.username_nonce,
            tag=encrypted_entry.username_tag
        ))
        password = decrypt_field(vault_manager.vault_key, EncryptionResult(
            ciphertext=encrypted_entry.password_cipher,
            nonce=encrypted_entry.password_nonce,
            tag=encrypted_entry.password_tag
        ))
        notes = decrypt_field(vault_manager.vault_key, EncryptionResult(
            ciphertext=encrypted_entry.notes_cipher,
            nonce=encrypted_entry.notes_nonce,
            tag=encrypted_entry.notes_tag
        ))
        url = decrypt_field(vault_manager.vault_key, EncryptionResult(
            ciphertext=encrypted_entry.url_cipher,
            nonce=encrypted_entry.url_nonce,
            tag=encrypted_entry.url_tag
        ))
        return Entry(
            entry_id=encrypted_entry.entry_id,
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            created_at=encrypted_entry.created_at,
            updated_at=encrypted_entry.updated_at
        )
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, DatabaseError, EntryNotFoundError, VaultError)):
            raise
        raise VaultError(f"Unexpected error getting entry: {e}")


def list_entries() -> List[Dict[str, str]]:
    """List all entries (titles and IDs only)."""
    try:
        vault_manager._ensure_vault_open()
        from src.db import get_all_entries as db_get_all_entries
        encrypted_entries = db_get_all_entries(vault_manager.vault_path)
        entries = []
        for encrypted_entry in encrypted_entries:
            title = decrypt_field(vault_manager.vault_key, EncryptionResult(
                ciphertext=encrypted_entry.title_cipher,
                nonce=encrypted_entry.title_nonce,
                tag=encrypted_entry.title_tag
            ))
            entries.append({
                "entry_id": encrypted_entry.entry_id,
                "title": title
            })
        return entries
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, DatabaseError, VaultError)):
            raise
        raise VaultError(f"Unexpected error listing entries: {e}")


def update_entry(entry_id: str, **kwargs) -> None:
    """Update an existing entry."""
    try:
        vault_manager._ensure_vault_open()
        from src.db import entry_exists as db_entry_exists, get_entry as db_get_entry, update_entry as db_update_entry
        if not db_entry_exists(vault_manager.vault_path, entry_id):
            raise EntryNotFoundError(f"Entry not found: {entry_id}")
        current_entry = get_entry(entry_id)
        updated_data = {
            "title": kwargs.get("title", current_entry.title),
            "username": kwargs.get("username", current_entry.username),
            "password": kwargs.get("password", current_entry.password),
            "url": kwargs.get("url", current_entry.url),
            "notes": kwargs.get("notes", current_entry.notes)
        }
        # Encrypt each field
        title_enc = encrypt_field(vault_manager.vault_key, updated_data["title"])
        username_enc = encrypt_field(vault_manager.vault_key, updated_data["username"])
        password_enc = encrypt_field(vault_manager.vault_key, updated_data["password"])
        notes_enc = encrypt_field(vault_manager.vault_key, updated_data["notes"])
        url_enc = encrypt_field(vault_manager.vault_key, updated_data["url"])
        encrypted_entry = EncryptedEntry(
            entry_id=entry_id,
            title_cipher=title_enc.ciphertext,
            title_nonce=title_enc.nonce,
            title_tag=title_enc.tag,
            username_cipher=username_enc.ciphertext,
            username_nonce=username_enc.nonce,
            username_tag=username_enc.tag,
            password_cipher=password_enc.ciphertext,
            password_nonce=password_enc.nonce,
            password_tag=password_enc.tag,
            notes_cipher=notes_enc.ciphertext,
            notes_nonce=notes_enc.nonce,
            notes_tag=notes_enc.tag,
            url_cipher=url_enc.ciphertext,
            url_nonce=url_enc.nonce,
            url_tag=url_enc.tag,
            created_at=current_entry.created_at,
            updated_at=vault_manager._get_current_timestamp()
        )
        db_update_entry(vault_manager.vault_path, entry_id, encrypted_entry)
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, DatabaseError, EntryNotFoundError, VaultError)):
            raise
        raise VaultError(f"Unexpected error updating entry: {e}")


def delete_entry(entry_id: str) -> None:
    """Delete a password entry."""
    try:
        vault_manager._ensure_vault_open()
        from src.db import delete_entry as db_delete_entry
        db_delete_entry(vault_manager.vault_path, entry_id)
        
    except Exception as e:
        if isinstance(e, (DatabaseError, EntryNotFoundError, VaultError)):
            raise
        raise VaultError(f"Unexpected error deleting entry: {e}")


def search_entries(query: str) -> List[Dict[str, str]]:
    """Search entries by title (case-insensitive)."""
    try:
        vault_manager._ensure_vault_open()
        
        all_entries = list_entries()
        query_lower = query.lower()
        
        return [entry for entry in all_entries 
                if query_lower in entry["title"].lower()]
        
    except Exception as e:
        if isinstance(e, VaultError):
            raise
        raise VaultError(f"Unexpected error searching entries: {e}")


def rekey_vault(new_master_password: str) -> None:
    """Change master password and re-encrypt vault key."""
    try:
        vault_manager._ensure_vault_open()
        
        if not new_master_password:
            raise ValidationError("New master password cannot be empty")
        
        # Create new KDF parameters
        new_kdf_params = create_kdf_params("argon2id")
        
        # Derive new master key
        new_master_key = derive_master_key(new_master_password, new_kdf_params.salt, new_kdf_params)
        
        # Re-encrypt vault key with new master key
        new_wrapped_vault_key = wrap_vault_key(new_master_key, vault_manager.vault_key)
        
        # Update vault configuration
        config = get_vault_meta(vault_manager.vault_path)
        config.kdf_salt = new_kdf_params.salt
        config.kdf_params = {
            "memory_cost": new_kdf_params.memory_cost,
            "parallelism": new_kdf_params.parallelism,
            "iterations": new_kdf_params.iterations,
            "hash_length": new_kdf_params.hash_length
        }
        config.encrypted_vault_key = new_wrapped_vault_key.ciphertext
        config.vault_key_nonce = new_wrapped_vault_key.nonce
        config.vault_key_tag = new_wrapped_vault_key.tag
        config.modified_at = vault_manager._get_current_timestamp()
        
        # Update database
        update_vault_meta(vault_manager.vault_path, config)
        
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, DatabaseError, VaultError)):
            raise
        raise VaultError(f"Unexpected error rekeying vault: {e}")


def export_vault() -> bytes:
    """Export vault as encrypted backup."""
    try:
        vault_manager._ensure_vault_open()
        
        # Get all entries
        all_entries = get_all_entries(vault_manager.vault_path)
        
        # Serialize entries data
        export_data = {
            "version": "1.0",
            "entries": [
                {
                    "entry_id": entry.entry_id,
                    "title_cipher": entry.title_cipher.hex(),
                    "title_nonce": entry.title_nonce.hex(),
                    "title_tag": entry.title_tag.hex(),
                    "username_cipher": entry.username_cipher.hex(),
                    "username_nonce": entry.username_nonce.hex(),
                    "username_tag": entry.username_tag.hex(),
                    "password_cipher": entry.password_cipher.hex(),
                    "password_nonce": entry.password_nonce.hex(),
                    "password_tag": entry.password_tag.hex(),
                    "notes_cipher": entry.notes_cipher.hex(),
                    "notes_nonce": entry.notes_nonce.hex(),
                    "notes_tag": entry.notes_tag.hex(),
                    "url_cipher": entry.url_cipher.hex(),
                    "url_nonce": entry.url_nonce.hex(),
                    "url_tag": entry.url_tag.hex(),
                    "created_at": entry.created_at,
                    "updated_at": entry.updated_at
                }
                for entry in all_entries
            ],
            "exported_at": vault_manager._get_current_timestamp()
        }
        
        # Convert to JSON bytes
        import json
        json_data = json.dumps(export_data).encode('utf-8')
        
        # Generate backup key and encrypt
        backup_key = generate_backup_key()
        encrypted_backup = encrypt_backup(json_data, backup_key)
        
        # Create final backup format
        backup_format = {
            "backup_key": backup_key.hex(),
            "encrypted_data": {
                "ciphertext": encrypted_backup.ciphertext.hex(),
                "nonce": encrypted_backup.nonce.hex(),
                "tag": encrypted_backup.tag.hex()
            }
        }
        
        return json.dumps(backup_format).encode('utf-8')
        
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, DatabaseError, VaultError)):
            raise
        raise VaultError(f"Unexpected error exporting vault: {e}")


def import_vault(backup_data: bytes) -> None:
    """Import entries from encrypted backup."""
    try:
        vault_manager._ensure_vault_open()
        
        import json
        
        # Parse backup format
        backup_format = json.loads(backup_data.decode('utf-8'))
        
        # Decrypt backup data
        backup_key = bytes.fromhex(backup_format["backup_key"])
        encrypted_data = EncryptionResult(
            ciphertext=bytes.fromhex(backup_format["encrypted_data"]["ciphertext"]),
            nonce=bytes.fromhex(backup_format["encrypted_data"]["nonce"]),
            tag=bytes.fromhex(backup_format["encrypted_data"]["tag"])
        )
        
        decrypted_data = decrypt_backup(encrypted_data, backup_key)
        export_data = json.loads(decrypted_data.decode('utf-8'))
        
        # Import entries by re-encrypting them with current vault key
        for entry_data in export_data["entries"]:
            # Create a temporary encrypted entry to decrypt the fields
            temp_encrypted_entry = EncryptedEntry(
                entry_id=entry_data["entry_id"],
                title_cipher=bytes.fromhex(entry_data["title_cipher"]),
                title_nonce=bytes.fromhex(entry_data["title_nonce"]),
                title_tag=bytes.fromhex(entry_data["title_tag"]),
                username_cipher=bytes.fromhex(entry_data["username_cipher"]),
                username_nonce=bytes.fromhex(entry_data["username_nonce"]),
                username_tag=bytes.fromhex(entry_data["username_tag"]),
                password_cipher=bytes.fromhex(entry_data["password_cipher"]),
                password_nonce=bytes.fromhex(entry_data["password_nonce"]),
                password_tag=bytes.fromhex(entry_data["password_tag"]),
                notes_cipher=bytes.fromhex(entry_data["notes_cipher"]),
                notes_nonce=bytes.fromhex(entry_data["notes_nonce"]),
                notes_tag=bytes.fromhex(entry_data["notes_tag"]),
                url_cipher=bytes.fromhex(entry_data["url_cipher"]),
                url_nonce=bytes.fromhex(entry_data["url_nonce"]),
                url_tag=bytes.fromhex(entry_data["url_tag"]),
                created_at=entry_data["created_at"],
                updated_at=entry_data["updated_at"]
            )
            
            # Decrypt the entry fields (this will fail if vault keys don't match)
            # For now, we'll assume the backup was created from the same vault
            # In a real implementation, you'd need the original vault key or password
            try:
                title = decrypt_field(vault_manager.vault_key, EncryptionResult(
                    ciphertext=temp_encrypted_entry.title_cipher,
                    nonce=temp_encrypted_entry.title_nonce,
                    tag=temp_encrypted_entry.title_tag
                ))
                username = decrypt_field(vault_manager.vault_key, EncryptionResult(
                    ciphertext=temp_encrypted_entry.username_cipher,
                    nonce=temp_encrypted_entry.username_nonce,
                    tag=temp_encrypted_entry.username_tag
                ))
                password = decrypt_field(vault_manager.vault_key, EncryptionResult(
                    ciphertext=temp_encrypted_entry.password_cipher,
                    nonce=temp_encrypted_entry.password_nonce,
                    tag=temp_encrypted_entry.password_tag
                ))
                notes = decrypt_field(vault_manager.vault_key, EncryptionResult(
                    ciphertext=temp_encrypted_entry.notes_cipher,
                    nonce=temp_encrypted_entry.notes_nonce,
                    tag=temp_encrypted_entry.notes_tag
                ))
                url = decrypt_field(vault_manager.vault_key, EncryptionResult(
                    ciphertext=temp_encrypted_entry.url_cipher,
                    nonce=temp_encrypted_entry.url_nonce,
                    tag=temp_encrypted_entry.url_tag
                ))
                
                # Re-encrypt with current vault key and add entry
                add_entry(title, username, password, url, notes)
                
            except AuthenticationError:
                # If decryption fails, the backup was created with a different vault key
                # Skip this entry or raise an error
                raise ValidationError("Cannot import entry: backup was created with a different vault key")
        
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, DatabaseError, VaultError)):
            raise
        raise VaultError(f"Unexpected error importing vault: {e}")


def get_vault_info() -> Dict[str, any]:
    """Get vault metadata and statistics."""
    try:
        vault_manager._ensure_vault_open()
        
        config = get_vault_meta(vault_manager.vault_path)
        entry_count = get_entry_count(vault_manager.vault_path)
        db_info = get_database_info(vault_manager.vault_path)
        
        return {
            "version": config.version,
            "kdf": config.kdf,
            "entry_count": entry_count,
            "created_at": config.created_at,
            "modified_at": config.modified_at,
            "file_size": db_info.get("file_size", 0),
            "vault_path": vault_manager.vault_path
        }
        
    except Exception as e:
        if isinstance(e, (DatabaseError, VaultError)):
            raise
        raise VaultError(f"Unexpected error getting vault info: {e}")


def change_master_password(old_password: str, new_password: str) -> None:
    """Change master password with old password verification."""
    try:
        # Verify old password by trying to open vault
        temp_vault_key = vault_manager.vault_key
        temp_vault_path = vault_manager.vault_path
        temp_is_open = vault_manager.is_open
        
        # Temporarily close vault
        vault_manager.vault_key = None
        vault_manager.vault_path = None
        vault_manager.is_open = False
        
        try:
            # Try to open with old password
            open_vault(old_password, temp_vault_path)
            
            # If successful, rekey with new password
            rekey_vault(new_password)
            
        except Exception:
            # Restore previous state
            vault_manager.vault_key = temp_vault_key
            vault_manager.vault_path = temp_vault_path
            vault_manager.is_open = temp_is_open
            raise AuthenticationError("Old password is incorrect")
        
    except Exception as e:
        if isinstance(e, (CryptoError, ValidationError, DatabaseError, AuthenticationError, VaultError)):
            raise
        raise VaultError(f"Unexpected error changing master password: {e}")


# Global vault manager instance
vault_manager = VaultManager()

