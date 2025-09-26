# Offline Password Manager

A secure, offline password manager built with Python and SQLite. This password manager stores your credentials locally with strong encryption and never sends data over the network.

## 🔒 Security Features

- **AES-256-GCM encryption** for all sensitive data
- **Argon2id KDF** for master key derivation (with PBKDF2 fallback)
- **Per-field encryption** with unique nonces and authentication tags
- **Secure password input** (no echo)
- **Authentication tags** to prevent tampering
- **Secure memory clearing** for sensitive data
- **Offline operation** - no network communication

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- Required packages: `cryptography`, `argon2-cffi`

### Installation

1. Clone this repository:
```bash
git clone <your-repo-url>
cd password-manager
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Usage

#### Initialize a new vault
```bash
python -m src.main init
```

#### Add a password entry
```bash
python -m src.main add
```

#### List all entries
```bash
python -m src.main list
```

#### Retrieve an entry
```bash
python -m src.main get <entry-id>
```

#### Update an entry
```bash
python -m src.main update <entry-id>
```

#### Delete an entry
```bash
python -m src.main delete <entry-id>
```

#### Change master password
```bash
python -m src.main rekey
```

#### Export backup
```bash
python -m src.main export backup.json
```

#### Import backup
```bash
python -m src.main import backup.json
```

#### Show vault information
```bash
python -m src.main info
```

## 📁 Project Structure

```
password-manager/
├── src/
│   ├── crypto.py          # Cryptographic primitives
│   ├── db.py              # Database layer
│   ├── vault.py           # Vault API layer
│   ├── cli.py             # Command-line interface
│   ├── main.py            # Entry point
│   └── test_*.py          # Unit tests
├── docs/
│   ├── requirements.md    # Functional requirements
│   ├── design.md          # System design
│   └── modules.md         # Module specifications
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🏗️ Architecture

The password manager follows a layered architecture:

1. **CLI Layer** (`cli.py`) - Handles user commands and input
2. **Vault API Layer** (`vault.py`) - Orchestrates operations and enforces encryption boundaries
3. **Database Layer** (`db.py`) - Handles SQLite persistence
4. **Crypto Layer** (`crypto.py`) - Implements all cryptographic primitives

## 🔧 Development

### Running Tests

```bash
# Run all tests
python -m src.test_crypto
python -m src.test_db
python -m src.test_vault

# Run CLI tests (requires mocking)
python -m src.test_cli
```

### Database Schema

The database uses two main tables:

- **`vault_meta`** - Stores vault configuration, KDF parameters, and encrypted vault key
- **`entries`** - Stores encrypted password entries with per-field nonces and tags

## ⚠️ Security Warnings

- **Master Password**: If you lose your master password, your data will be permanently lost
- **Backup**: Always create regular backups of your vault
- **Environment**: Run only on trusted systems
- **Updates**: Keep dependencies updated for security patches

## 📋 Requirements

### Functional Requirements
- ✅ Vault initialization and unlocking
- ✅ Entry CRUD operations (Create, Read, Update, Delete)
- ✅ Strong encryption (AES-256-GCM)
- ✅ Master password change (rekey)
- ✅ Backup/export functionality
- ✅ CLI commands as specified
- ✅ Secure password input

### Non-Functional Requirements
- ✅ All sensitive data encrypted at rest
- ✅ CSPRNG for keys/salts/nonces
- ✅ Clear error messages without leaking secrets
- ✅ Performance targets met
- ✅ Cross-platform compatibility

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built following TDD (Test-Driven Development) principles
- Uses industry-standard cryptographic libraries
- Follows security best practices for password managers
