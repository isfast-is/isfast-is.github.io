#!/usr/bin/env python3
"""Encrypt projects.json -> projects.enc for the Ísfast team landing page (isfast-is.github.io).

Usage: python3 encrypt.py            (passphrase read from .passphrase file)
       python3 encrypt.py "newpass"  (also writes the new passphrase to .passphrase)

projects.json and .passphrase are gitignored — only projects.enc is published.
Parameters must match the WebCrypto code in index.html:
PBKDF2-SHA256 / 300000 iterations / 16-byte salt -> AES-256-GCM / 12-byte IV.
"""
import base64
import json
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
PASS_FILE = os.path.join(HERE, ".passphrase")

if len(sys.argv) > 1:
    passphrase = sys.argv[1]
    with open(PASS_FILE, "w") as f:
        f.write(passphrase)
else:
    with open(PASS_FILE) as f:
        passphrase = f.read().strip()

with open(os.path.join(HERE, "projects.json"), "rb") as f:
    plaintext = f.read()
json.loads(plaintext)  # fail fast on invalid JSON

salt = os.urandom(16)
iv = os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                 iterations=300000).derive(passphrase.encode())
ciphertext = AESGCM(key).encrypt(iv, plaintext, None)

b64 = lambda b: base64.b64encode(b).decode()
with open(os.path.join(HERE, "projects.enc"), "w") as f:
    json.dump({"salt": b64(salt), "iv": b64(iv), "data": b64(ciphertext)}, f)

print("projects.enc written")
