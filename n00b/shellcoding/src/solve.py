from pwn import *

NUM_LEVELS = 7

for i in range(1, NUM_LEVELS + 1):
    print("testing level {}".format(i))

    code = open("n00b{}.s".format(i), "r").read()
    r = remote("localhost", 4242)
    r.recvuntil("(Y/N) ")
    r.sendline("n")

    r.recvuntil("Level: ")
    r.sendline(str(i))

    r.recvuntil("EOF")
    r.recvline()

    r.sendline(code + "\n" + "EOF")
    resp = r.recvall()
    r.close()

    resp = filter(lambda x: x != "", resp.split("\n"))
    flag = resp[-1].strip()

    print(resp)

    assert flag == open("n00b{}_flag.txt".format(i), "r").read().strip()
    print("level {} OK!".format(i))
