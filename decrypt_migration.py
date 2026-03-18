#!/usr/bin/env python3
"""
decrypt_migration.py — Decrypt kvstore migration export from old server.

Reads migration_export.json (12 AES-GCM encrypted records from datastore.downes.ca),
prompts for the old kvstore passphrase at runtime, decrypts each value using the
same PBKDF2+AES-GCM scheme as crypto_utils.js, and writes migration_decrypted.json.

Encryption scheme (must match crypto_utils.js):
  base64_decode(value) → bytes: [salt(16) | iv(12) | ciphertext(rest)]
  key = PBKDF2-HMAC-SHA256(passphrase, salt, iterations=100000, key_len=32)
  plaintext = AES-GCM-decrypt(key, iv, ciphertext)
"""

import json
import base64
import getpass
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Missing dependency. Run: pip install cryptography")
    sys.exit(1)

INPUT_FILE  = Path(__file__).parent / "migration_export.json"
OUTPUT_FILE = Path(__file__).parent / "migration_decrypted.json"


def derive_key(passphrase_bytes: bytes, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256, 100k iterations, 32-byte key — matches crypto_utils.js deriveKey()."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passphrase_bytes)


def decrypt_value(passphrase_bytes: bytes, combined_b64: str) -> str:
    """Decrypt a single base64-encoded [salt|iv|ciphertext] value."""
    combined = base64.b64decode(combined_b64)
    salt       = combined[:16]
    iv         = combined[16:28]
    ciphertext = combined[28:]
    key = derive_key(passphrase_bytes, salt)
    plaintext = AESGCM(key).decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")


def main():
    if not INPUT_FILE.exists():
        print(f"Input file not found: {INPUT_FILE}")
        sys.exit(1)

    with open(INPUT_FILE) as f:
        records = json.load(f)

    print(f"Loaded {len(records)} records from {INPUT_FILE.name}")
    passphrase = getpass.getpass("Enter your old kvstore passphrase: ").encode("utf-8")

    decrypted = []
    errors = []

    for record in records:
        key = record.get("key", "")
        try:
            plaintext = decrypt_value(passphrase, record["value"])
            decrypted.append({"key": key, "value": plaintext})
            print(f"  OK  {key}")
        except Exception as e:
            errors.append(key)
            print(f"  FAIL {key}: {e}")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(decrypted, f, indent=2)

    print(f"\nWrote {len(decrypted)} decrypted records to {OUTPUT_FILE.name}")
    if errors:
        print(f"Failed: {errors}")
        print("Wrong passphrase, or those records used a different key.")


if __name__ == "__main__":
    main()
