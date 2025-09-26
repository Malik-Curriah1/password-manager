"""
CLI module for the Offline Password Manager.

This module handles command line interface, user input, and delegates
operations to the vault layer.
"""

import sys
import argparse
import json
from getpass import getpass
from pathlib import Path
from typing import Optional

from src.vault import (
    init_vault, open_vault, close_vault, is_vault_open,
    add_entry, get_entry, list_entries, update_entry, delete_entry,
    rekey_vault, export_vault, import_vault, get_vault_info,
    VaultError, EntryNotFoundError, ValidationError, AuthenticationError
)


def main():
    """Entry point — dispatch commands from sys.argv."""
    parser = argparse.ArgumentParser(
        description="Offline Password Manager",
        prog="vault"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize a new vault')
    init_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    
    # Open command
    open_parser = subparsers.add_parser('open', help='Unlock vault for current session')
    open_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a new password entry')
    add_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Retrieve and show a password entry')
    get_parser.add_argument('entry_id', help='Entry ID to retrieve')
    get_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    get_parser.add_argument('--copy', action='store_true', help='Copy password to clipboard')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List available entries (titles only)')
    list_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update an existing entry')
    update_parser.add_argument('entry_id', help='Entry ID to update')
    update_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete an entry')
    delete_parser.add_argument('entry_id', help='Entry ID to delete')
    delete_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    
    # Rekey command
    rekey_parser = subparsers.add_parser('rekey', help='Change master password')
    rekey_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export encrypted backup')
    export_parser.add_argument('filepath', help='Backup file path')
    export_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    
    # Import command
    import_parser = subparsers.add_parser('import', help='Import encrypted backup')
    import_parser.add_argument('filepath', help='Backup file path')
    import_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show vault information')
    info_parser.add_argument('--vault', default='vault.db', help='Vault file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'init':
            cmd_init(args.vault)
        elif args.command == 'open':
            cmd_open(args.vault)
        elif args.command == 'add':
            cmd_add(args.vault)
        elif args.command == 'get':
            cmd_get(args.entry_id, args.vault, args.copy)
        elif args.command == 'list':
            cmd_list(args.vault)
        elif args.command == 'update':
            cmd_update(args.entry_id, args.vault)
        elif args.command == 'delete':
            cmd_delete(args.entry_id, args.vault)
        elif args.command == 'rekey':
            cmd_rekey(args.vault)
        elif args.command == 'export':
            cmd_export(args.filepath, args.vault)
        elif args.command == 'import':
            cmd_import(args.filepath, args.vault)
        elif args.command == 'info':
            cmd_info(args.vault)
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)
    except (VaultError, EntryNotFoundError, ValidationError, AuthenticationError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


def cmd_init(vault_path: str = "vault.db") -> None:
    """Initialize a new vault."""
    try:
        print("Initializing new vault...")
        master_password = confirm_master_password()
        
        init_vault(master_password, vault_path)
        print(f"Vault initialized successfully at {vault_path}")
        print("⚠️  WARNING: If you lose your master password, your data will be permanently lost!")
        
    except Exception as e:
        raise VaultError(f"Failed to initialize vault: {e}")


def cmd_open(vault_path: str = "vault.db") -> None:
    """Unlock vault for current session."""
    try:
        if not Path(vault_path).exists():
            raise VaultError(f"Vault file not found: {vault_path}")
        
        master_password = get_master_password("Master password: ")
        open_vault(master_password, vault_path)
        print("Vault unlocked successfully")
        
    except Exception as e:
        raise VaultError(f"Failed to open vault: {e}")


def cmd_add(vault_path: str = "vault.db") -> None:
    """Add a new password entry."""
    try:
        if not is_vault_open():
            cmd_open(vault_path)
        
        print("Adding new password entry...")
        title = input("Title: ").strip()
        username = input("Username: ").strip()
        password = getpass("Password: ")
        url = input("URL (optional): ").strip()
        notes = input("Notes (optional): ").strip()
        
        if not title or not username or not password:
            raise ValidationError("Title, username, and password are required")
        
        entry_id = add_entry(title, username, password, url, notes)
        print(f"Entry added successfully with ID: {entry_id}")
        
    except Exception as e:
        raise VaultError(f"Failed to add entry: {e}")


def cmd_get(entry_id: str, vault_path: str = "vault.db", copy_password: bool = False) -> None:
    """Retrieve and show a password entry."""
    try:
        if not is_vault_open():
            cmd_open(vault_path)
        
        entry = get_entry(entry_id)
        
        print(f"\nEntry Details:")
        print(f"ID: {entry.entry_id}")
        print(f"Title: {entry.title}")
        print(f"Username: {entry.username}")
        print(f"Password: {'*' * len(entry.password)}")
        print(f"URL: {entry.url}")
        print(f"Notes: {entry.notes}")
        print(f"Created: {entry.created_at}")
        print(f"Updated: {entry.updated_at}")
        
        if copy_password:
            try:
                import pyperclip
                pyperclip.copy(entry.password)
                print("\nPassword copied to clipboard!")
            except ImportError:
                print("\nTo copy passwords to clipboard, install pyperclip: pip install pyperclip")
            except Exception as e:
                print(f"\nFailed to copy password: {e}")
        
    except Exception as e:
        raise VaultError(f"Failed to get entry: {e}")


def cmd_list(vault_path: str = "vault.db") -> None:
    """List available entries (titles only)."""
    try:
        if not is_vault_open():
            cmd_open(vault_path)
        
        entries = list_entries()
        
        if not entries:
            print("No entries found.")
            return
        
        print(f"\nFound {len(entries)} entries:")
        print("-" * 50)
        for entry in entries:
            print(f"ID: {entry['entry_id']}")
            print(f"Title: {entry['title']}")
            print("-" * 50)
        
    except Exception as e:
        raise VaultError(f"Failed to list entries: {e}")


def cmd_update(entry_id: str, vault_path: str = "vault.db") -> None:
    """Update an existing entry."""
    try:
        if not is_vault_open():
            cmd_open(vault_path)
        
        # Get current entry
        current_entry = get_entry(entry_id)
        
        print(f"Updating entry: {current_entry.title}")
        print("Press Enter to keep current value, or enter new value")
        
        title = input(f"Title [{current_entry.title}]: ").strip()
        username = input(f"Username [{current_entry.username}]: ").strip()
        password = getpass("Password (press Enter to keep current): ")
        url = input(f"URL [{current_entry.url}]: ").strip()
        notes = input(f"Notes [{current_entry.notes}]: ").strip()
        
        # Prepare update data
        update_data = {}
        if title:
            update_data['title'] = title
        if username:
            update_data['username'] = username
        if password:
            update_data['password'] = password
        if url:
            update_data['url'] = url
        if notes:
            update_data['notes'] = notes
        
        if update_data:
            update_entry(entry_id, **update_data)
            print("Entry updated successfully")
        else:
            print("No changes made")
        
    except Exception as e:
        raise VaultError(f"Failed to update entry: {e}")


def cmd_delete(entry_id: str, vault_path: str = "vault.db") -> None:
    """Delete an entry."""
    try:
        if not is_vault_open():
            cmd_open(vault_path)
        
        # Get entry details for confirmation
        entry = get_entry(entry_id)
        
        print(f"Are you sure you want to delete entry '{entry.title}'?")
        confirm = input("Type 'yes' to confirm: ").strip().lower()
        
        if confirm == 'yes':
            delete_entry(entry_id)
            print("Entry deleted successfully")
        else:
            print("Deletion cancelled")
        
    except Exception as e:
        raise VaultError(f"Failed to delete entry: {e}")


def cmd_rekey(vault_path: str = "vault.db") -> None:
    """Change master password (re-encrypt vault key)."""
    try:
        if not is_vault_open():
            cmd_open(vault_path)
        
        print("Changing master password...")
        current_password = get_master_password("Current master password: ")
        
        # Verify current password by trying to open vault
        close_vault()
        try:
            open_vault(current_password, vault_path)
        except Exception:
            raise AuthenticationError("Current password is incorrect")
        
        new_password = confirm_master_password()
        
        rekey_vault(new_password)
        print("Master password changed successfully")
        
    except Exception as e:
        raise VaultError(f"Failed to change master password: {e}")


def cmd_export(filepath: str, vault_path: str = "vault.db") -> None:
    """Export encrypted backup."""
    try:
        if not is_vault_open():
            cmd_open(vault_path)
        
        print("Exporting vault...")
        backup_data = export_vault()
        
        with open(filepath, 'wb') as f:
            f.write(backup_data)
        
        print(f"Vault exported successfully to {filepath}")
        
    except Exception as e:
        raise VaultError(f"Failed to export vault: {e}")


def cmd_import(filepath: str, vault_path: str = "vault.db") -> None:
    """Import encrypted backup."""
    try:
        if not is_vault_open():
            cmd_open(vault_path)
        
        if not Path(filepath).exists():
            raise VaultError(f"Backup file not found: {filepath}")
        
        print("Importing vault...")
        with open(filepath, 'rb') as f:
            backup_data = f.read()
        
        import_vault(backup_data)
        print("Vault imported successfully")
        
    except Exception as e:
        raise VaultError(f"Failed to import vault: {e}")


def cmd_info(vault_path: str = "vault.db") -> None:
    """Show vault information."""
    try:
        if not is_vault_open():
            cmd_open(vault_path)
        
        info = get_vault_info()
        
        print(f"\nVault Information:")
        print(f"Version: {info['version']}")
        print(f"KDF: {info['kdf']}")
        print(f"Entry count: {info['entry_count']}")
        print(f"Created: {info['created_at']}")
        print(f"Modified: {info['modified_at']}")
        print(f"File size: {info['file_size']} bytes")
        print(f"Vault path: {info['vault_path']}")
        
    except Exception as e:
        raise VaultError(f"Failed to get vault info: {e}")


def get_master_password(prompt: str = "Master password: ") -> str:
    """Securely prompt for master password."""
    try:
        password = getpass(prompt)
        if not password:
            raise ValidationError("Master password cannot be empty")
        return password
    except KeyboardInterrupt:
        raise KeyboardInterrupt("Operation cancelled")


def confirm_master_password() -> str:
    """Prompt for master password with confirmation."""
    try:
        password1 = getpass("Master password: ")
        password2 = getpass("Confirm master password: ")
        
        if password1 != password2:
            raise ValidationError("Passwords do not match")
        
        if not password1:
            raise ValidationError("Master password cannot be empty")
        
        return password1
    except KeyboardInterrupt:
        raise KeyboardInterrupt("Operation cancelled")


if __name__ == "__main__":
    main()