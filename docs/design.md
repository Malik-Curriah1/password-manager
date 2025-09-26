# Offline Password Manager — Design Document

## 1. Overview
This design specifies the internal architecture for the **Offline Password Manager** built in Python + SQLite.  
It defines modules, their responsibilities, and how encryption and persistence are handled.  

---

## 2. System Architecture

### High-Level Layers
1. **CLI Layer (`cli.py`)**
   - Handles user commands (`init`, `open`, `add`, `get`, etc.).
   - Collects user input (master password, entry details).
   - Calls into Vault API.

2. **Vault API Layer (`vault.py`)**
   - Orchestrates all operations (vault init, open, CRUD).
   - Mediates between **DB** and **Crypto** layers.
   - Enforces encryption boundaries (all sensitive data encrypted before DB insert, decrypted only after fetch).

3. **Database Layer (`db.py`)**
   - Handles SQLite persistence.
   - Stores only ciphertext, nonces, and metadata.
   - Provides CRUD wrappers for entries and vault metadata.

4. **Crypto Layer (`crypto.py`)**
   - Implements all cryptographic primitives.
   - Responsible for:
     - Deriving master key
     - Wrapping/unwrapping vault key
     - Encrypting/decrypting entries

---

## 3. Module Responsibilities

### 3.1 CLI (`cli.py`)
- Parses commands (e.g., `vault add`).
- Uses `getpass` for secure password input.
- Delegates logic to `vault.py`.

### 3.2 Vault API (`vault.py`)
Functions:
- `init_vault(master_password)`
  - Derives master key, generates vault key, stores encrypted vault key in DB.
- `open_vault(master_password)`
  - Verifies password, unlocks vault by decrypting vault key.
- `add_entry(title, username, password, url, notes)`
  - Calls crypto layer to encrypt entry.
  - Calls DB layer to insert encrypted entry.
- `get_entry(entry_id)`
  - Fetches ciphertext, decrypts entry, returns plaintext.
- `update_entry(entry_id, fields)`
  - Similar to `add_entry` but updates DB row.
- `delete_entry(entry_id)`
  - Removes entry from DB.
- `rekey_vault(new_master_password)`
  - Derives new master key, re-encrypts vault key, updates metadata.

### 3.3 Database Layer (`db.py`)
Tables:
- **`vault_meta`**
  - Stores schema version, KDF params, salt, encrypted vault key.
- **`entries`**
  - Stores ciphertext blobs, nonce, AEAD tag, and metadata.
Responsibilities:
- Initialize DB schema.
- Insert/update/delete entries.
- Retrieve vault metadata.

### 3.4 Crypto Layer (`crypto.py`)
Functions:
- `derive_master_key(password, salt, params)`
  - Uses Argon2id (preferred) or PBKDF2 fallback.
- `wrap_vault_key(master_key, vault_key)`
  - Encrypts vault key using AES-GCM with a fresh nonce.
- `unwrap_vault_key(master_key, wrapped_blob)`
  - Decrypts vault key.
- `encrypt_entry(vault_key, plaintext_entry)`
  - Serializes entry fields (JSON).
  - Generates nonce, encrypts with AES-GCM.
  - Returns `(ciphertext, nonce, tag)`.
- `decrypt_entry(vault_key, ciphertext_blob)`
  - Uses AES-GCM with nonce + vault_key to restore plaintext entry.

---

## 4. Data Flow (Encryption Boundaries)

### Initialization (`init`)
1. User enters master password.
2. Derive `master_key` from password.
3. Generate random `vault_key`.
4. Encrypt vault_key with master_key → store in `vault_meta`.

### Opening (`open`)
1. User enters master password.
2. Derive `master_key`.
3. Decrypt vault_key from `vault_meta`.
4. Keep vault_key in memory for session.

### Adding Entry (`add`)
1. Collect plaintext entry data.
2. Pass to `crypto.encrypt_entry(vault_key, entry)`.
3. Store ciphertext, nonce, tag in DB.

### Retrieving Entry (`get`)
1. Fetch ciphertext blob from DB.
2. Pass to `crypto.decrypt_entry(vault_key, blob)`.
3. Return plaintext entry to CLI.

### Rekey (`rekey`)
1. User provides new master password.
2. Derive new master_key.
3. Re-encrypt vault_key with new master_key.
4. Update `vault_meta`.

---

## 5. Database Schema (Detailed)

### Table: `vault_meta`
| Column             | Type    | Notes                                  |
|--------------------|---------|----------------------------------------|
| id                 | INTEGER | Primary key (single row)               |
| version            | TEXT    | Schema version                         |
| kdf                | TEXT    | e.g., "argon2id"                       |
| kdf_salt           | BLOB    | Random salt for KDF                    |
| kdf_params         | TEXT    | JSON with Argon2 params                |
| encrypted_vault_key| BLOB    | Vault key wrapped with master key      |
| created_at         | TEXT    | Timestamp                              |
| modified_at        | TEXT    | Timestamp                              |

### Table: `entries`
| Column        | Type    | Notes                                   |
|---------------|---------|-----------------------------------------|
| entry_id      | TEXT    | UUID primary key                        |
| title_cipher  | BLOB    | Encrypted title (or plaintext, if chosen)|
| username_cipher| BLOB   | Encrypted username                      |
| password_cipher| BLOB   | Encrypted password                      |
| notes_cipher  | BLOB    | Encrypted notes                         |
| url_cipher    | BLOB    | Encrypted URL                           |
| nonce         | BLOB    | Random nonce for AES-GCM                |
| tag           | BLOB    | Authentication tag from AES-GCM         |
| created_at    | TEXT    | Timestamp                               |
| updated_at    | TEXT    | Timestamp                               |

---

## 6. Security Considerations
- Argon2id for master key derivation (strong KDF).
- AES-256-GCM or ChaCha20-Poly1305 for encryption.
- Unique nonce per encryption.
- Secrets only decrypted in memory during use.
- Clipboard clearing for copied passwords.
- Vault auto-lock after inactivity.

---

## 7. CLI Commands (Flow Summary)

- `init` → Creates a new vault.
- `open` → Unlocks vault for session.
- `add` → Encrypts and stores entry.
- `get` → Decrypts and shows entry.
- `list` → Shows titles of entries.
- `update` → Modifies an entry.
- `delete` → Removes an entry.
- `export` / `import` → Encrypted backup/restore.
- `rekey` → Change master password.

---

## 8. Future Extensions
- GUI (`gui.py`).
- Deterministic encryption for searchable titles.
- Browser autofill integration.
- Multi-vault support.
- Secure remote sync (end-to-end encrypted).

