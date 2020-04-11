#!/usr/bin/env python3
import secrets
import hashlib

# This script creates a password where the second byte in the sha256
# sum is zero.

while(True):
    password = secrets.token_hex(32)
    enc = hashlib.sha256()
    enc.update(bytes(password, 'ascii'))
    digest = enc.digest()
    if (digest[0] > 0) and (digest[1] == 0):
        with open("/hack/password.txt", "w+") as f:
            f.write(password)
        break
