# Writeup [Ransomware Part 1](./README.md)

## Task description
**Author: Kakekongen**

**Difficulty: challenging**

**Category: crypto**

Someone managed to get themselves infected and had ransomware running on their
computer, encrypting a directory containing some important files before
deleting itself from the system. We were not able to extract the actual
ransomware binary, only an object file left behind in the `/tmp` directory.
Luckily, we were capturing the current network traffic.

Are you able to decrypt the encrypted files for us?

**WARNING: The ransomware object file is part of actual ransomware which WILL encrypt and delete your files if linked and executed, which without the key are lost!**

Here are the aforementioned files:
- [Ransomware object file](uploads/ransomware.o)
- [Ransomed files](uploads/ransomed_files.zip)
- [Network capture](uploads/network_capture.pcapng)

---

## Writeup
In this task, we are presented with a [ransomware](https://en.wikipedia.org/wiki/Ransomware)
[object file](https://en.wikipedia.org/wiki/Object_file)
that has encrypted a directory of files. We are also given a network dump of
the time around when the ransomware was run. The network dump is provided to
enable us to determine the randomly generated key.

By reversing the ransomware object file, we determine that the files are
encrypted using the [RC6](https://en.wikipedia.org/wiki/RC6) cipher in
[CBC mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC).

In addition, we can determine that the IV is randomly generated per file
and is stored as the first block in the encrypted file.

We see that after the ransomware has encrypted all files in the directory,
it will send a single HTTP GET request where the
[path of the URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)
is the key encoded as a hex-string.

By skimming through the network capture, we can extract the key, which
in our case is `D189BF6C31C10AF5B467F9BD147C49C5`.

This enables us to write a decryption program that will use the key,
read the first 16 bytes as the IV and use that information to
decrypt the rest of the file, yielding the plaintext.

As we have multiple files named `flag_X.txt`, we should decrypt all of them.

You can find a possible decryption program in the [writeup directory](writeup/)

After decrypting all the files, we can extract the flag from `flag_3.txt`.

Yielding the flag: `TG20{luckily_you_managed_to_recover_the_key}`.
