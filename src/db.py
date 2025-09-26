"""
Database module for the Offline Password Manager.

This module handles SQLite persistence for vault metadata and encrypted entries.
"""

import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from dataclasses import dataclass

from src.crypto import EncryptionResult


@dataclass
class VaultConfig:
    """Vault configuration parameters."""
    version: str
    kdf: str
    kdf_salt: bytes
    kdf_params: Dict[str, any]
    encrypted_vault_key: bytes
    vault_key_nonce: bytes
    vault_key_tag: bytes
    created_at: str
    modified_at: str


@dataclass
class EncryptedEntry:
    """Encrypted entry data structure."""
    entry_id: str
    title_cipher: bytes
    title_nonce: bytes
    title_tag: bytes
    username_cipher: bytes
    username_nonce: bytes
    username_tag: bytes
    password_cipher: bytes
    password_nonce: bytes
    password_tag: bytes
    notes_cipher: bytes
    notes_nonce: bytes
    notes_tag: bytes
    url_cipher: bytes
    url_nonce: bytes
    url_tag: bytes
    created_at: str
    updated_at: str


class DatabaseError(Exception):
    """Raised when database operations fail."""
    pass


class VaultNotFoundError(DatabaseError):
    """Raised when vault file doesn't exist."""
    pass


class EntryNotFoundError(DatabaseError):
    """Raised when entry doesn't exist."""
    pass


class DatabaseManager:
    """Manages database connections and operations."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
    
    def connect(self) -> None:
        """Establish database connection."""
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.execute("PRAGMA foreign_keys = ON")
        except Exception as e:
            raise DatabaseError(f"Failed to connect to database: {e}")
    
    def disconnect(self) -> None:
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


def init_database(db_path: str) -> None:
    """Initialize database with schema."""
    try:
        # Create directory if it doesn't exist
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            # Check if vault_meta table exists and has the correct schema
            cursor.execute("PRAGMA table_info(vault_meta)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if not columns:
                # Create vault_meta table from scratch
                cursor.execute("""
                    CREATE TABLE vault_meta (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        version TEXT NOT NULL,
                        kdf TEXT NOT NULL,
                        kdf_salt BLOB NOT NULL,
                        kdf_params TEXT NOT NULL,
                        encrypted_vault_key BLOB NOT NULL,
                        vault_key_nonce BLOB NOT NULL,
                        vault_key_tag BLOB NOT NULL,
                        created_at TEXT NOT NULL,
                        modified_at TEXT NOT NULL
                    )
                """)
            elif 'vault_key_nonce' not in columns:
                # Migrate old schema to new schema
                cursor.execute("""
                    CREATE TABLE vault_meta_new (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        version TEXT NOT NULL,
                        kdf TEXT NOT NULL,
                        kdf_salt BLOB NOT NULL,
                        kdf_params TEXT NOT NULL,
                        encrypted_vault_key BLOB NOT NULL,
                        vault_key_nonce BLOB NOT NULL,
                        vault_key_tag BLOB NOT NULL,
                        created_at TEXT NOT NULL,
                        modified_at TEXT NOT NULL
                    )
                """)
                
                # Copy data from old table (split encrypted_vault_key into ciphertext + tag)
                cursor.execute("""
                    INSERT INTO vault_meta_new 
                    SELECT id, version, kdf, kdf_salt, kdf_params, 
                           substr(encrypted_vault_key, 1, length(encrypted_vault_key) - 16) as encrypted_vault_key,
                           substr(encrypted_vault_key, -16) as vault_key_nonce,
                           substr(encrypted_vault_key, -16) as vault_key_tag,
                           created_at, modified_at
                    FROM vault_meta
                """)
                
                cursor.execute("DROP TABLE vault_meta")
                cursor.execute("ALTER TABLE vault_meta_new RENAME TO vault_meta")
            
            # Check if entries table exists and has the correct schema
            cursor.execute("PRAGMA table_info(entries)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if not columns:
                # Create entries table from scratch
                cursor.execute("""
                    CREATE TABLE entries (
                        entry_id TEXT PRIMARY KEY,
                        title_cipher BLOB NOT NULL,
                        title_nonce BLOB NOT NULL,
                        title_tag BLOB NOT NULL,
                        username_cipher BLOB NOT NULL,
                        username_nonce BLOB NOT NULL,
                        username_tag BLOB NOT NULL,
                        password_cipher BLOB NOT NULL,
                        password_nonce BLOB NOT NULL,
                        password_tag BLOB NOT NULL,
                        notes_cipher BLOB NOT NULL,
                        notes_nonce BLOB NOT NULL,
                        notes_tag BLOB NOT NULL,
                        url_cipher BLOB NOT NULL,
                        url_nonce BLOB NOT NULL,
                        url_tag BLOB NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
            elif 'title_nonce' not in columns:
                # Migrate old entries schema to new schema
                cursor.execute("""
                    CREATE TABLE entries_new (
                        entry_id TEXT PRIMARY KEY,
                        title_cipher BLOB NOT NULL,
                        title_nonce BLOB NOT NULL,
                        title_tag BLOB NOT NULL,
                        username_cipher BLOB NOT NULL,
                        username_nonce BLOB NOT NULL,
                        username_tag BLOB NOT NULL,
                        password_cipher BLOB NOT NULL,
                        password_nonce BLOB NOT NULL,
                        password_tag BLOB NOT NULL,
                        notes_cipher BLOB NOT NULL,
                        notes_nonce BLOB NOT NULL,
                        notes_tag BLOB NOT NULL,
                        url_cipher BLOB NOT NULL,
                        url_nonce BLOB NOT NULL,
                        url_tag BLOB NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                
                # Copy data from old table (use existing nonce/tag for all fields)
                cursor.execute("""
                    INSERT INTO entries_new 
                    SELECT entry_id, title_cipher, nonce, tag,
                           username_cipher, nonce, tag,
                           password_cipher, nonce, tag,
                           notes_cipher, nonce, tag,
                           url_cipher, nonce, tag,
                           created_at, updated_at
                    FROM entries
                """)
                
                cursor.execute("DROP TABLE entries")
                cursor.execute("ALTER TABLE entries_new RENAME TO entries")
            
            db.connection.commit()
    
    except Exception as e:
        raise DatabaseError(f"Failed to initialize database: {e}")


def create_vault_meta(db_path: str, config: VaultConfig) -> None:
    """Store vault metadata."""
    try:
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            # Convert kdf_params to JSON string
            kdf_params_json = json.dumps(config.kdf_params)
            
            cursor.execute("""
                INSERT OR REPLACE INTO vault_meta 
                (id, version, kdf, kdf_salt, kdf_params, encrypted_vault_key, vault_key_nonce, vault_key_tag, created_at, modified_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                config.version,
                config.kdf,
                config.kdf_salt,
                kdf_params_json,
                config.encrypted_vault_key,
                config.vault_key_nonce,
                config.vault_key_tag,
                config.created_at,
                config.modified_at
            ))
            
            db.connection.commit()
    
    except Exception as e:
        raise DatabaseError(f"Failed to create vault metadata: {e}")


def get_vault_meta(db_path: str) -> VaultConfig:
    """Retrieve vault metadata."""
    try:
        if not Path(db_path).exists():
            raise VaultNotFoundError(f"Vault file not found: {db_path}")
        
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            cursor.execute("SELECT * FROM vault_meta WHERE id = 1")
            row = cursor.fetchone()
            
            if not row:
                raise VaultNotFoundError("Vault metadata not found")
            
            # Parse kdf_params from JSON
            kdf_params = json.loads(row[4])
            
            return VaultConfig(
                version=row[1],
                kdf=row[2],
                kdf_salt=row[3],
                kdf_params=kdf_params,
                encrypted_vault_key=row[5],
                vault_key_nonce=row[6],
                vault_key_tag=row[7],
                created_at=row[8],
                modified_at=row[9]
            )
    
    except Exception as e:
        if isinstance(e, (DatabaseError, VaultNotFoundError)):
            raise
        raise DatabaseError(f"Failed to get vault metadata: {e}")


def update_vault_meta(db_path: str, config: VaultConfig) -> None:
    """Update vault metadata."""
    try:
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            # Convert kdf_params to JSON string
            kdf_params_json = json.dumps(config.kdf_params)
            
            cursor.execute("""
                UPDATE vault_meta SET
                    version = ?, kdf = ?, kdf_salt = ?, kdf_params = ?,
                    encrypted_vault_key = ?, vault_key_nonce = ?, vault_key_tag = ?, modified_at = ?
                WHERE id = 1
            """, (
                config.version,
                config.kdf,
                config.kdf_salt,
                kdf_params_json,
                config.encrypted_vault_key,
                config.vault_key_nonce,
                config.vault_key_tag,
                config.modified_at
            ))
            
            if cursor.rowcount == 0:
                raise VaultNotFoundError("Vault metadata not found")
            
            db.connection.commit()
    
    except Exception as e:
        if isinstance(e, (DatabaseError, VaultNotFoundError)):
            raise
        raise DatabaseError(f"Failed to update vault metadata: {e}")


def insert_entry(db_path: str, encrypted_entry: EncryptedEntry) -> None:
    """Insert encrypted entry into database."""
    try:
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            cursor.execute("""
                INSERT INTO entries 
                (entry_id, title_cipher, title_nonce, title_tag, username_cipher, username_nonce, username_tag, password_cipher, password_nonce, password_tag, notes_cipher, notes_nonce, notes_tag, url_cipher, url_nonce, url_tag, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                encrypted_entry.entry_id,
                encrypted_entry.title_cipher,
                encrypted_entry.title_nonce,
                encrypted_entry.title_tag,
                encrypted_entry.username_cipher,
                encrypted_entry.username_nonce,
                encrypted_entry.username_tag,
                encrypted_entry.password_cipher,
                encrypted_entry.password_nonce,
                encrypted_entry.password_tag,
                encrypted_entry.notes_cipher,
                encrypted_entry.notes_nonce,
                encrypted_entry.notes_tag,
                encrypted_entry.url_cipher,
                encrypted_entry.url_nonce,
                encrypted_entry.url_tag,
                encrypted_entry.created_at,
                encrypted_entry.updated_at
            ))
            
            db.connection.commit()
    
    except Exception as e:
        raise DatabaseError(f"Failed to insert entry: {e}")


def get_entry(db_path: str, entry_id: str) -> EncryptedEntry:
    """Retrieve encrypted entry by ID."""
    try:
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            cursor.execute("SELECT * FROM entries WHERE entry_id = ?", (entry_id,))
            row = cursor.fetchone()
            
            if not row:
                raise EntryNotFoundError(f"Entry not found: {entry_id}")
            
            return EncryptedEntry(
                entry_id=row[0],
                title_cipher=row[1],
                title_nonce=row[2],
                title_tag=row[3],
                username_cipher=row[4],
                username_nonce=row[5],
                username_tag=row[6],
                password_cipher=row[7],
                password_nonce=row[8],
                password_tag=row[9],
                notes_cipher=row[10],
                notes_nonce=row[11],
                notes_tag=row[12],
                url_cipher=row[13],
                url_nonce=row[14],
                url_tag=row[15],
                created_at=row[16],
                updated_at=row[17]
            )
    
    except Exception as e:
        if isinstance(e, (DatabaseError, EntryNotFoundError)):
            raise
        raise DatabaseError(f"Failed to get entry: {e}")


def get_all_entries(db_path: str) -> List[EncryptedEntry]:
    """Retrieve all encrypted entries."""
    try:
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            cursor.execute("SELECT * FROM entries ORDER BY created_at")
            rows = cursor.fetchall()
            
            entries = []
            for row in rows:
                entries.append(EncryptedEntry(
                    entry_id=row[0],
                    title_cipher=row[1],
                    title_nonce=row[2],
                    title_tag=row[3],
                    username_cipher=row[4],
                    username_nonce=row[5],
                    username_tag=row[6],
                    password_cipher=row[7],
                    password_nonce=row[8],
                    password_tag=row[9],
                    notes_cipher=row[10],
                    notes_nonce=row[11],
                    notes_tag=row[12],
                    url_cipher=row[13],
                    url_nonce=row[14],
                    url_tag=row[15],
                    created_at=row[16],
                    updated_at=row[17]
                ))
            
            return entries
    
    except Exception as e:
        raise DatabaseError(f"Failed to get all entries: {e}")


def get_entry_titles(db_path: str) -> List[Dict[str, str]]:
    """Get entry IDs and encrypted titles for listing."""
    try:
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            cursor.execute("SELECT entry_id, title_cipher, title_nonce, title_tag FROM entries ORDER BY created_at")
            rows = cursor.fetchall()
            
            return [{"entry_id": row[0], "title_cipher": row[1], "title_nonce": row[2], "title_tag": row[3]} for row in rows]
    
    except Exception as e:
        raise DatabaseError(f"Failed to get entry titles: {e}")


def update_entry(db_path: str, entry_id: str, encrypted_entry: EncryptedEntry) -> None:
    """Update encrypted entry in database."""
    try:
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            cursor.execute("""
                UPDATE entries SET
                    title_cipher = ?, title_nonce = ?, title_tag = ?,
                    username_cipher = ?, username_nonce = ?, username_tag = ?,
                    password_cipher = ?, password_nonce = ?, password_tag = ?,
                    notes_cipher = ?, notes_nonce = ?, notes_tag = ?,
                    url_cipher = ?, url_nonce = ?, url_tag = ?,
                    updated_at = ?
                WHERE entry_id = ?
            """, (
                encrypted_entry.title_cipher,
                encrypted_entry.title_nonce,
                encrypted_entry.title_tag,
                encrypted_entry.username_cipher,
                encrypted_entry.username_nonce,
                encrypted_entry.username_tag,
                encrypted_entry.password_cipher,
                encrypted_entry.password_nonce,
                encrypted_entry.password_tag,
                encrypted_entry.notes_cipher,
                encrypted_entry.notes_nonce,
                encrypted_entry.notes_tag,
                encrypted_entry.url_cipher,
                encrypted_entry.url_nonce,
                encrypted_entry.url_tag,
                encrypted_entry.updated_at,
                entry_id
            ))
            
            if cursor.rowcount == 0:
                raise EntryNotFoundError(f"Entry not found: {entry_id}")
            
            db.connection.commit()
    
    except Exception as e:
        if isinstance(e, (DatabaseError, EntryNotFoundError)):
            raise
        raise DatabaseError(f"Failed to update entry: {e}")


def delete_entry(db_path: str, entry_id: str) -> None:
    """Delete entry from database."""
    try:
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            cursor.execute("DELETE FROM entries WHERE entry_id = ?", (entry_id,))
            
            if cursor.rowcount == 0:
                raise EntryNotFoundError(f"Entry not found: {entry_id}")
            
            db.connection.commit()
    
    except Exception as e:
        if isinstance(e, (DatabaseError, EntryNotFoundError)):
            raise
        raise DatabaseError(f"Failed to delete entry: {e}")


def entry_exists(db_path: str, entry_id: str) -> bool:
    """Check if entry exists in database."""
    try:
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            cursor.execute("SELECT 1 FROM entries WHERE entry_id = ?", (entry_id,))
            return cursor.fetchone() is not None
    
    except Exception as e:
        raise DatabaseError(f"Failed to check if entry exists: {e}")


def get_entry_count(db_path: str) -> int:
    """Get total number of entries."""
    try:
        with DatabaseManager(db_path) as db:
            cursor = db.connection.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM entries")
            return cursor.fetchone()[0]
    
    except Exception as e:
        raise DatabaseError(f"Failed to get entry count: {e}")


def close_connection(db_path: str) -> None:
    """Close database connection."""
    # This is handled by the DatabaseManager context manager
    pass


def backup_database(source_path: str, backup_path: str) -> None:
    """Create backup of database file."""
    try:
        import shutil
        Path(backup_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, backup_path)
    except Exception as e:
        raise DatabaseError(f"Failed to backup database: {e}")


def restore_database(backup_path: str, target_path: str) -> None:
    """Restore database from backup."""
    try:
        import shutil
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, target_path)
    except Exception as e:
        raise DatabaseError(f"Failed to restore database: {e}")


def get_database_info(db_path: str) -> Dict[str, any]:
    """Get database statistics and information."""
    try:
        if not Path(db_path).exists():
            return {"exists": False}
        
        file_size = Path(db_path).stat().st_size
        entry_count = get_entry_count(db_path)
        
        return {
            "exists": True,
            "file_size": file_size,
            "entry_count": entry_count,
            "path": db_path
        }
    
    except Exception as e:
        raise DatabaseError(f"Failed to get database info: {e}")

