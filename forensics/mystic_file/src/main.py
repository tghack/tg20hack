#! /usr/local/bin/python3.6
import os
import uuid
ramdisk_path = "/mnt"
def create_ramdisk():
    os.system("mdmfs -s 5m md1 {}".format(ramdisk_path))

def create_disk():
    os.system("truncate -s 10m weird.dd")
    os.system("mdconfig -u md3 weird.dd")
    os.system("newfs /dev/md3")
    os.system("mount /dev/md3 /mnt")
def unmount():
    os.system("rm {}/*".format(ramdisk_path))
    os.system("umount {}".format(ramdisk_path))
    os.system("mdconfig -du md3")
def create_file(filename, uid):
    open(filename, "w").close()
    os.chown(filename, uid, 42)


def main():
    flag = "python3.7 -c 'import os; x=\"VGhlIGdyZWF0IGFybXkgb2YgTW90aGVycyBoYWNrZXJzIGlzIHJldHVybmluZyEgV2UgSEFDS0VEIHlvdXIgc2VydmVyIHRvIHNob3cgb3VyIGNhcGFiaWxpdGllcyBhbmQgdG8gd2FzdGUgeW91ciB2YWx1YWJsZSB0aW1lLiBCdXQsIGR1ZSB0byB5b3VyIGdyZWF0IGVmZm9ydCB3ZSBhcmUgZ2l2aW5nIHlvdSBhIGZsYWc6IFRHMjB7RmlsZXN5c3RlbV9hdHRyaWJ1dGVzX2lzX2FfbmVhdF9tZXRob2Rfb2ZfaGlkaW5nX2luZm9ybWF0aW9ufQ==\"; os.system(\"echo {} | b64decode -r\".format(x))'"
    create_disk()
    for i, c in enumerate(flag):
        filename = "{}/{}".format(ramdisk_path, str(uuid.uuid4().hex))
        create_file(filename, ord(c))
    unmount()
if __name__ == "__main__":
    main()
