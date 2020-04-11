#!/usr/bin/env python3
from cryptography.fernet import Fernet
from binascii import unhexlify
from base64 import b64encode
from subprocess import call, DEVNULL
from sys import argv


def decrypt(cipher, key):
    return Fernet(key).decrypt(cipher)


def main():
    if len(argv) < 4:
        print(f"Usage: {argv[0]} <pubkey_file> <cipher_key_file> <ciphertext>")
        return -1

    print(f"Cracking encapsulated key...")
    call(["sage", "edonk-attack.sage", argv[1], argv[2], "secret.txt"],
         stdout=DEVNULL,
         stderr=DEVNULL)

    print(f"Cracked encapsulated key...")
    with open(argv[3]) as f:
        enc_flag = f.read().strip().encode()
    with open("secret.txt") as f:
        secret = b64encode(unhexlify(f.read().strip()))
    print(f"Decrypted flag: {decrypt(enc_flag, secret).decode()}")


if __name__ == "__main__":
    main()
