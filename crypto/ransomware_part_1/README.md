# Ransomware Part 1
**Author: Kakekongen**

**Difficulty: challenging**

**Category: crypto**

---

Someone managed to get themselves infected and had ransomware running on their
computer, encrypting a directory containing some important files before
deleting itself from the system. We were not able to extract the actual
ransomware binary, only an object file left behind in the `/tmp` directory.
Luckily, we were capturing the current network traffic.

Are you able to decrypt the encrypted files for us?

**WARNING: The ransomware object file is part of actual ransomware which WILL encrypt and delete your files if linked and executed, which without the key are lost!**

Relevant files:
- [Ransomware object file](uploads/ransomware.o)
- [Ransomed files](uploads/ransomed_files.zip)
- [Network capture](uploads/network_capture.pcapng)
