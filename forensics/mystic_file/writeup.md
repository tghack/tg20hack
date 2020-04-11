# Writeup [Mystic file](README.md)
**Author: odin**

**Difficulty: challenging**

**Category: forensic** 

---

A mystic file has been found in one of the critical servers used to develop military weapons out of the valuable crystals. One of the high ranking officers has given you the task to identify the real purpose of this file. Can you find it?



[Download Mystic file](uploads/passwd.png).

```
2fe72bd845d4fa35d61fa22aae32d951  passwd.png
```



# Solution

1. Looking into the file with `xxd`, it is possible to guess that the file is XOR encrypted. This pattern is often seen when null bytes are XORed. 0x2a ^ 0x0 = 0x42

```
» xxd weird.dd.xor | head
00000000: 2a2a 2a2a 2a2a 2a2a 2a2a 2a2a 2a2a 2a2a  ****************
00000010: 2a2a 2a2a 2a2a 2a2a 2a2a 2a2a 2a2a 2a2a  ****************
00000020: 2a2a 2a2a 2a2a 2a2a 2a2a 2a2a 2a2a 2a2a  ****************
```

2. Decrypting the file reveals that it is a UFS filesystem (FreeBSD here):

```console
» file weird.dd
weird.dd: Unix Fast File system [v2] (little-endian) last mounted on /mnt, last written at Thu Feb 20 18:52:37 2020, clean flag 1, readonly flag 0, number of blocks 2560, number of data blocks 2375, number of cylinder groups 4, block size 32768, fragment size 4096, average file size 16384, average number of files in dir 64, pending blocks to free 0, pending inodes to free 0, system-wide uuid 0, minimum percentage of free blocks 8, TIME optimization
```

3. Running `fls` on the file does not give us much value. But looking into deleted files, it is possible to see several interesting files. `fls -rd` 
4. The most interesting to view is the file permissions, which is abnormal. Trying to decode some of them shows that this is hex chars.
5. It is possible to assume that information is hidden in the user permissions. If the information is written in a sequence, the files can be ranked based on the _inode_ number.


The following script below makes it possible to decrypt the XOR file and extract the information from the user permissions:

```python
import subprocess
import sys

def xor(filename):
    data = bytearray(open(filename, "rb").read())
    for i in range(len(data)):
        data[i] ^= 42
    open(filename + ".decoded", "wb").write(data)


def fls_to_flag(filename):
    flag = ""
    output = subprocess.check_output(["fls", "-rld", filename])
    output = output.split("\n".encode())
    for x in output[:-1]:
        x = x.split("\t".encode())
        flag += chr(int(x[-1]))
    print(flag)




def main():
    filename = sys.argv[1]

    xor(filename)
    fls_to_flag(filename + ".decoded")


main()
```

The output of this execution:

```bash
python3.7 -c 'import os; x="VGhlIGdyZWF0IGFybXkgb2YgTW90aGVycyBoYWNrZXJzIGlzIHJldHVybmluZyEgV2UgSEFDS0VEIHlvdXIgc2VydmVyIHRvIHNob3cgb3VyIGNhcGFiaWxpdGllcyBhbmQgdG8gd2FzdGUgeW91ciB2YWx1YWJsZSB0aW1lLiBCdXQsIGR1ZSB0byB5b3VyIGdyZWF0IGVmZm9ydCB3ZSBhcmUgZ2l2aW5nIHlvdSBhIGZsYWc6IFRHMjB7RmlsZXN5c3RlbV9hdHRyaWJ1dGVzX2lzX2FfbmVhdF9tZXRob2Rfb2ZfaGlkaW5nX2luZm9ybWF0aW9ufQ=="; os.system("echo {} | b64decode -r".format(x))'
```

The base64 decodes to:

```
The great army of Mothers hackers is returning! We HACKED your server to show our capabilities and to waste your valuable time. But, due to your great effort we are giving you a flag: TG20{Filesystem_attributes_is_a_neat_method_of_hiding_information}
```
