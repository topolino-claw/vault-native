# Development Notes

## Local Encryption with Vault Password

When creating a new vault, the user should be prompted to set up a master password.
This password is used to encrypt all vault data locally (at rest) before anything touches disk or storage.

- **Skip option**: The setup flow should allow the user to skip setting a password (unencrypted local storage, current behavior).
- **Encryption scope**: Everything stored locally — credentials, notes, keys — gets encrypted with the master password.
- **No multi-account in the same browser**: This design ties local encryption to a single vault/password. Multiple accounts in the same browser instance were never a real use case and would complicate the encryption model for no practical benefit. One vault = one password = one encrypted blob.
- **Unlock flow**: On app launch, if a password was set, prompt the user to unlock before any data is decrypted and loaded.
