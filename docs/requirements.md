# Offline Password Manager — Requirements

## 1. Introduction

### Purpose
This project is a **secure offline password manager** implemented in Python with SQLite for local persistence.  
It stores and manages credentials (usernames, passwords, notes, etc.) with strong encryption, never sending data over a network.

### Scope
- Secure storage of credentials.
- Encrypted with a master password.
- Local-only, no network sync in MVP.
- Provides CLI for management.
- Backup and rekey supported.

---

## 2. Functional Requirements

### Vault Management
- **FR-1:** Initialize a new vault with a master password.
- **FR-2:** Derive master key using a KDF (Argon2id preferred).
- **FR-3:** Generate a vault key and encrypt it with the master key.
- **FR-4:** Store vault metadata (version, salt, KDF params, encrypted vault key).
- **FR-5:** Unlock vault by re-deriving master key and decrypting vault key.

### Entry Management
- **FR-6:** Add entries with fields: title, username, password, URL, notes.
- **FR-7:** Encrypt entry fields before storage.
- **FR-8:** Retrieve and decrypt entries.
- **FR-9:** Update entries.
- **FR-10:** Delete entries.

### Security & Encryption
- **FR-11:** Use AES-256-GCM (or ChaCha20-Poly1305) for encryption.
- **FR-12:** Generate random nonces for each encryption.
- **FR-13:** Store only ciphertext, never plaintext secrets.
- **FR-14:** Verify authenticity using AEAD tags.
- **FR-15:** Auto-lock vault after inactivity (timeout).

### Backup & Export
- **FR-16:** Support direct backup of vault file.
- **FR-17:** Support encrypted export and import of entries.
- **FR-18:** Allow rekeying (change master password).

### User Interface
- **FR-19:** Provide CLI commands:
  - `init` → Create new vault
  - `open` → Unlock vault
  - `add` → Add entry
  - `get` → Retrieve entry
  - `list` → Show entry titles
  - `update` → Modify entry
  - `delete` → Remove entry
  - `export` / `import` → Backup and restore
  - `rekey` → Change master password
- **FR-20:** Passwords entered securely (no echo).
- **FR-21:** Never print secrets unless explicitly requested.

---

## 3. Non-Functional Requirements

### Security
- **NFR-1:** All sensitive data encrypted at rest.
- **NFR-2:** Keys, salts, nonces generated with CSPRNG.
- **NFR-3:** Minimize plaintext lifetime in memory.
- **NFR-4:** No sensitive data logged.

### Performance
- **NFR-5:** Vault opening completes within 2–3s with recommended KDF.
- **NFR-6:** Entry add/retrieval < 200ms.

### Reliability
- **NFR-7:** Schema includes versioning for migrations.
- **NFR-8:** Export/import compatible across versions.

### Usability
- **NFR-9:** Warn user: lost master password = permanent data loss.
- **NFR-10:** Provide clear error messages without leaking secrets.

---

## 4. Database Schema (Abstract)

### Table: `vault_meta`
- `id` (primary key, single row)
- `version`
- `kdf` (string)
- `kdf_salt` (binary)
- `kdf_params` (JSON/text)
- `encrypted_vault_key` (binary)
- `created_at`, `modified_at`

### Table: `entries`
- `entry_id` (UUID, primary key)
- `title_cipher` (binary or plaintext)
- `username_cipher` (binary)
- `password_cipher` (binary)
- `notes_cipher` (binary)
- `url_cipher` (binary)
- `nonce` (binary)
- `tag` (binary)
- `created_at`, `updated_at`

---

## 5. System Flow

1. **Init:** Master password → master key → vault key → encrypted vault key → DB.
2. **Open:** Password → master key → decrypt vault key → vault unlocked.
3. **Add Entry:** Plaintext entry → encrypt with vault key → store ciphertext.
4. **Get Entry:** Fetch ciphertext → decrypt with vault key → plaintext output.
5. **Rekey:** New master password → new master key → re-encrypt vault key.
6. **Export/Import:** Serialize entries in encrypted format → restore into vault.

---

## 6. Constraints
- Python 3.9+
- SQLite for storage
- PyCA Cryptography (or equivalent)
- Must run fully offline
- Cross-platform (Linux, Windows, macOS)

---

## 7. Future Extensions
- GUI (Tkinter, PyQt)
- Searchable encrypted titles
- Browser autofill integration
- Optional cloud sync with end-to-end encryption
