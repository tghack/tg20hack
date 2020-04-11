#!/usr/bin/env python3
import binascii
from capstone import *
import sys
from unicorn import *
from unicorn.x86_const import *
from keystone import *
import random
import traceback


# TODO
# - prettier printing

SYS_exit = 60
# number of instructions to skip when single-stepping
nskip = 0

call_0_template = """
push    {}
call    func
ret
func:
"""

call_1_template = """
push    {}
mov     rdi, {}
call    func
ret
func:
"""

call_2_template = """
push    {}
mov     rdi, {}
mov     rsi, {}
call    func
ret
func:
"""

md = Cs(CS_ARCH_X86, CS_MODE_64)
last_instruction = ""
single_step_mode = False


def dump_regs(uc):
    rax = uc.reg_read(UC_X86_REG_RAX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    rsp = uc.reg_read(UC_X86_REG_RSP)
    rip = uc.reg_read(UC_X86_REG_RIP)
    r8 = uc.reg_read(UC_X86_REG_R8)
    r9 = uc.reg_read(UC_X86_REG_R9)
    r10 = uc.reg_read(UC_X86_REG_R10)
    r11 = uc.reg_read(UC_X86_REG_R11)
    r12 = uc.reg_read(UC_X86_REG_R12)
    r13 = uc.reg_read(UC_X86_REG_R13)
    r14 = uc.reg_read(UC_X86_REG_R14)
    r15 = uc.reg_read(UC_X86_REG_R15)
    print("RAX: {:#x}".format(rax))
    print("RBX: {:#x}".format(rbx))
    print("RCX: {:#x}".format(rcx))
    print("RDX: {:#x}".format(rdx))
    print("RSI: {:#x}".format(rsi))
    print("RDI: {:#x}".format(rdi))
    print("RBP: {:#x}".format(rbp))
    print("RSP: {:#x}".format(rsp))


def print_single_step_menu(uc):
    dump_regs(uc)


def hook_code(uc, address, size, user_data):
    global last_instruction, single_step_mode, nskip
    code = uc.mem_read(address, size)
    for i in md.disasm(code, address):
        if single_step_mode:
            if nskip == 0:
                print_single_step_menu(uc)
                print("{:#x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))
                print("Press enter to step")
                input("> ")
            else:
                nskip -= 1
        else:
            print("{:#x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))

        last_instruction = i.mnemonic
        if i.mnemonic == "syscall":
            print("stopping emulation!")
            uc.emu_stop()
        break


def level1_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    if rax != 0:
        return False
    return True


def level2_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    rsi = uc.reg_read(UC_X86_REG_RSI)

    return all((
            rax == 42, 
            rbx == 13, 
            rcx == 37, 
            rdi == 0, 
            rsi == 1337
    ))


# TODO: validate div instruction
def level3_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    return rax == (args[0] // 4)


def level4_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    print(rax)
    return rax == 0


def level5_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    return rax == ((args[0] * 4) + 3)


def level6_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    return rax == (args[0] * args[1])


def level7_check(uc, args):
    rax = uc.reg_read(UC_X86_REG_RAX)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    return (rax == SYS_exit) and (rdi == 42) and (last_instruction == "syscall")


checks = {
    1: level1_check,
    2: level2_check,
    3: level3_check,
    4: level4_check,
    5: level5_check,
    6: level6_check,
    7: level7_check
}


def print_flag(level):
    if level == 1:
        print("TG20{welcome_to_the_world_of_assembly}")
    elif level == 2:
        print("TG20{some_setup_required}")
    elif level == 3:
        print("TG20{look_ma_im_a_math_wiz}")
    elif level == 4:
        print("TG20{is_this_functional_programming?}")
    elif level == 5:
        print("TG20{parameters_sure_are_nice_to_have}")
    elif level == 6:
        print("TG20{two_parameters!}")
    elif level == 7:
        print("TG20{good_bye_noob_hello_shellcode}")


def level_needs_call(level):
    return level in [4, 5, 6]


def check(uc, level, args):
    return checks[level](uc, args)


def do_emu(level, code, single_step):
    global single_step_mode, nskip

    if code is None:
        print("Please enter some code!")
        return

    addr = 0x1000
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    single_step_mode = single_step

    random.seed()
    args = random.sample(range(1, 10000), 3)

    # TODO: decrease stack size
    mu.mem_map(addr, 2 * 1024 * 1024)
    if level_needs_call(level):
        if level == 4:
            template = call_0_template.format(0xbadcafe)
            nskip = 2
        elif level == 5:
            template = call_1_template.format(0xbadcafe, args[0])
            nskip = 3
        elif level == 6:
            template = call_2_template.format(0xbadcafe, args[0], args[1])
            nskip = 4

        code = template + code
        code = asm_to_bytes(code)

        mu.mem_write(addr, code)

        # call levels needs a valid stack pointer
        mu.reg_write(UC_X86_REG_RSP, addr + (2 * 1024 * 1024))
    else:
        code = asm_to_bytes(code)
        mu.mem_write(addr, code)

    mu.hook_add(UC_HOOK_CODE, hook_code, addr, addr + len(code))
    if level == 3:
        mu.reg_write(UC_X86_REG_RAX, args[0])
    else:
        mu.reg_write(UC_X86_REG_RAX, 0xdeadbeefcafe)

    # TODO: clobber other registers?

    try:
        mu.emu_start(addr, addr + len(code))
    except UcError as e:
        pass

    print("Emulation done!")
    dump_regs(mu)

    if check(mu, level, args):
        print("Level {} successful!".format(level))
        print_flag(level)
    else:
        print("Level {} failed!".format(level))


def asm_to_bytes(code):
    print("code: {}".format(code))
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(code)

    if (encoding is None) or (count == 0):
        print("Couldn't compile your code :(")
        sys.exit()

    return bytes(encoding)


def main():
    single_step = False

    print("Welcome!")
    if input("Do you want single-step mode? (Y/N) ").upper() == "Y":
        single_step = True

    try:
        level = int(input("Level: "))
    except:
        print("Invalid level!")
        sys.exit()

    if level not in checks:
        print("Invalid level: {}".format(level))
        return False

    print("Please give me some assembly code, end with EOF")
    code = ""
    cnt = 0
    while True:
        cnt += 1

        if cnt == 100:
            print("Maximum numbers of instructions exceeded!")
            sys.exit()

        tmp = input("").lstrip() + "\n"
        if "EOF" in tmp:
            break

        code += tmp

    do_emu(level, code, single_step)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("error!")
#        traceback.print_exc()
#        print("main() error!: {}".format(e))
    sys.exit()
