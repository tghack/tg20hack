# Writeup [zero](./README.md)

## Challenge description
**Author: roypur**

**Difficulty: hard**

**Category: web/crypto**

We were able to leak some source code from a login page to a webserver run by Mother.
Are you able to gain access to the website?

- [hash.c](uploads/hash.c)
- [zero.tghack.no](https://zero.tghack.no)

---

## Writeup

The source code you got with this challenge is responsible for hashing the password
the user entered on the webpage. The password hashing is vulnerable because we have
used `strnlen` on the digest returned from nettle. Nettle returns the digest
as bytes, not an actual string, and can therefore contain a null byte before the end.

When `strnlen` calculates the length of a string it counts the number of
characters before the first null byte. The input of
the second hashing function will therefore be truncated
when the output of the first hashing function contains one or more null bytes.

The end result is that a password that would otherwise have been secure
can now be very insecure since many other passwords would generate the same hash.

```C
#include <nettle/sha2.h>
#include <nettle/sha3.h>
#include <string.h>

#define BUF_SIZE 128

void compute_sha3_256(char *digest, char *str) {
    struct sha3_256_ctx ctx = {0};
    sha3_256_init(&ctx);
    sha3_256_update(&ctx, strnlen(str, BUF_SIZE), str);
    sha3_256_digest(&ctx, SHA3_256_DIGEST_SIZE, digest);
}

void compute_sha256(char *digest, char *str) {
    struct sha256_ctx ctx = {0};
    sha256_init(&ctx);
    sha256_update(&ctx, strnlen(str, BUF_SIZE), str);
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);
}

void compute_hash(char *digest, char *password) {
    char sha256_dgst[BUF_SIZE + 1] = {0};
    compute_sha256(sha256_dgst, password);
    compute_sha3_256(digest, sha256_dgst);
}
```

Since the hashing function called first is the `sha256` function,
we need to create some passwords that end up having a null byte early in the output digest.
Since this is in a CTF, we can assume that the null byte is in either
the first or second byte of the digest, meaning we have to generate 256 passwords.

In the process of generating the 256 passwords we need,
you have to generate a lot more than 256 passwords since many
of them will have digests starting with the same bytes.

In our solve script we had to create around 270 000 different
passwords to get the 256 we wanted. It took less than
a second to generate, so it shouldn't be a problem. However, trying all 270 000 passwords
against the web server instead of 256 would be too slow.

```python3
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
```

To test all the passwords we generated we can use
the python requests library. The following code searches for
TG20 in the resulting web page. If TG20 is found, we print the content of the web page.

```python3
def try_passwords(passwords, endpoint):
    for password in passwords:
        res = requests.post(url = endpoint, data = {'password': password})
        if "TG20" in res.text:
            print(res.text)
            return
```

The contents of the webpage is printed, and we get the token

```
TG20{strlen_is_bad_mkay}
```
