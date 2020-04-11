import sys
import struct

magic_bytes = b"CRYPTO"

instruction_map = {
    "CompileEncryptionEngine": lambda x: [x],
    "LoadEncryptionEngine": lambda x: [x],
    "InitEncryptionEngine": lambda x: x.split(maxsplit=1),
    "ConnectAndSend": lambda x: x.split(maxsplit=2),
    "EncryptData": lambda x: x.split(maxsplit=1),
    "GetEntropy": lambda x: [x],
    "LoadData": lambda x: x.split(maxsplit=2),
    "SetShiftlSetTmp": lambda x: x.split(maxsplit=1),
    "SetShiftrSetTmp": lambda x: x.split(maxsplit=1),
    "SetXorSetTmp": lambda x: x.split(maxsplit=1),
    "SetAddSetTmp": lambda x: x.split(maxsplit=1),
    "SetSubSetTmp": lambda x: x.split(maxsplit=1),
    "SetShiftlTmp": lambda x: [x],
    "SetShiftrTmp": lambda x: [x],
    "SetXorTmp": lambda x: [x],
    "SetAddTmp": lambda x: [x],
    "SetSubTmp": lambda x: [x],
    "SetShiftl": lambda x: x.split(maxsplit=1),
    "Setshiftr": lambda x: x.split(maxsplit=1),
    "SetXor": lambda x: x.split(maxsplit=1),
    "SetAdd": lambda x: x.split(maxsplit=1),
    "SetSub": lambda x: x.split(maxsplit=1),
    "Stop": lambda x: [x],
    "Start": lambda x: [x],
}

prev_instr = 0


def encrypt_data(data, opcode):
    enc = [opcode]
    for byte in data.encode():
        enc.append(byte ^ enc[-1])
    return bytes(enc[1:])


opcode = lambda x: (struct.pack("B", instruction_strings[x[0]]^prev_instr))
op_reg = lambda x: (opcode(x) + struct.pack("<B", int(x[1])))
op_imm = lambda x: (opcode(x) + struct.pack("<Q", int(x[1])))
op_2reg = lambda x: (opcode(x) + struct.pack("<BB", int(x[1]), int(x[2])))
op_reg_imm = lambda x: (opcode(x) + struct.pack("<BQ", int(x[1]), len(x[2])) + encrypt_data(x[2], instruction_strings[x[0]]))

assemble_map = {
    "CompileEncryptionEngine": opcode,
    "LoadEncryptionEngine": opcode,
    "InitEncryptionEngine": op_reg,
    "ConnectAndSend": op_2reg,
    "EncryptData": op_reg, #op_encrypt,
    "GetEntropy": opcode,
    "LoadData": op_reg_imm,
    "SetShiftlSetTmp": op_imm,
    "SetShiftrSetTmp": op_imm,
    "SetXorSetTmp": op_imm,
    "SetAddSetTmp": op_imm,
    "SetSubSetTmp": op_imm,
    "SetShiftlTmp": opcode,
    "SetShiftrTmp": opcode,
    "SetXorTmp": opcode,
    "SetAddTmp": opcode,
    "SetSubTmp": opcode,
    "SetShiftl": op_imm,
    "Setshiftr": op_imm,
    "SetXor": op_imm,
    "SetAdd": op_imm,
    "SetSub": op_imm,
    "Stop": opcode,
    "Start": opcode,
}

instruction_strings = {
    "CompileEncryptionEngine": 0,
    "LoadEncryptionEngine": 1,
    "InitEncryptionEngine": 2,
    "ConnectAndSend": 3,
    "EncryptData": 4,
    "GetEntropy": 5,
    "LoadData": 6,
    "SetShiftlSetTmp": 7,
    "SetShiftrSetTmp": 8,
    "SetXorSetTmp": 9,
    "SetAddSetTmp": 10,
    "SetSubSetTmp": 11,
    "SetShiftlTmp": 12,
    "SetShiftrTmp": 13,
    "SetXorTmp": 14,
    "SetAddTmp": 15,
    "SetSubTmp": 16,
    "SetShiftl": 17,
    "Setshiftr": 18,
    "SetXor": 19,
    "SetAdd": 20,
    "SetSub": 21,
    "Stop": 22,
    "Start": 0xa4,
}


def read_file(program_file):
    with open(program_file, "r") as f:
        lines = map(lambda x: x.strip(), f.read().strip().split('\n'))

    return lines


def translate_instruction(token):
    try:
        instr, _args = token.split(maxsplit=1)
    # Catch those that can't be split
    except ValueError:
        return instruction_map[token](token)
    else:
        return instruction_map[instr](token)
    prev_instr


def assemble(translated_token):
    global prev_instr
    asm = assemble_map[translated_token[0]](translated_token)
    prev_instr = instruction_strings[translated_token[0]]
    return asm


def main(program_file):
    global magic_bytes
    tokens = read_file(program_file)
    translated_tokens = map(translate_instruction, tokens)
    assembled_tokens = map(assemble, translated_tokens)
    with open(program_file+".out", "wb+") as f:
        f.write(magic_bytes + b"".join(assembled_tokens))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
    else:
        main(sys.argv[1])
