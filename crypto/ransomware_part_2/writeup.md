# Writeup [Ransomware Part 2](./README.md)

## Task description
**Author: Kakekongen**

**Difficulty: hard**

**Category: crypto**

---

Again, someone managed to get their computed infected, resulting in some of
their important files being encrypted for ransom.
This time around, we did not only manage to recover one of
the object files, but the entire ransomware binary.

On the other hand, we were not capturing the network traffic at the time
when the ransomware was being run.

Hopefully, you are able to decrypt the ransomed files for us!

If it helps, the hostname of the machine is `ubuntu-server`.

**WARNING: The ransomware binary is actual ransomwhare which WILL encrypt and delete your files if executed, which without the key are lost!**

Relevant files:
- [Ransomware binary](uploads/ransomware)
- [Ransomed files](uploads/ransomed_files.zip)

---

## Writeup
In this task, we are presented with mostly the same
[ransomware](https://en.wikipedia.org/wiki/Ransomware) as in `Ransomware Part 1`
but this time, we have the actual binary, and not just an object file, meaning
we also have access to the function that will generate the random key.
In addition, we receive a compressed directory of encrypted files.

By reversing the ransomware object file, we determine that the files are
encrypted using the [RC6](https://en.wikipedia.org/wiki/RC6) cipher in
[CBC mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC).

In addition, we can determine that the IV is randomly generated per file
and is stored as the first block in the encrypted file.

We see that after the ransomware has encrypted all files in the directory,
it will send a single HTTP GET request where the
[path of the URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)
is the key encoded as a hex-string.
Though this is of no help to us, as we do not have a network capture.

With the whole binary, we can determine how the key was generated, and by
reversing the binary, we see that it uses the PID of the program in addition
to a number of system files that have a finite number of possible values.

The PID provides 16 bit of entropy, while the system files only provide a few
extra bits of entropy.

We already know the hostname of the system as it is given by the challenge text
and the system files are specific to the different versions of ubuntu.

This enables us to write a program that will use the hosname, limited
possible system files and brute force the PID in order to get a candidate key.
Further the program can read the first 16 bytes as the IV and use that
information together with the candidate key to try and decrypt the rest of the
file, hopefully yielding the plaintext.
If the PID does not match, we need to try a different one.

A good idea would be to search the decrypted file contents for the substring
`TG20`, which marks the flag, and is probably only present in decrypted files
where the correct key has been guessed.

You can find a possible decryption program in the [writeup directory](writeup/)

After running the program which also searces for the `TG20` substring, we
manage to find the right key and decrypt the correct flag file.

Yielding the flag: `TG20{luckily_not_all_ransomware_properly_generates_random_keys}`.
