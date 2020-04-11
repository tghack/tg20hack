import sys


# Generate the key stream based on seed
def lfsr_stream(start_state, length):
    stream = []

    lfsr = start_state
    # Define a round
    for i in range(length):
        lfsr ^= (lfsr >> 7) & 0xffff
        lfsr ^= (lfsr << 9) & 0xffff
        lfsr ^= (lfsr >> 13) & 0xffff
        lfsr &= 0xffff
        stream.append(lfsr & 0xff)
    return bytes(stream)


# Decrypt bytes
def xor_bytes(cipher, key):
    return bytes([c ^ k for (c, k) in zip(cipher, key)])


def main(encrypted_b64):
    # Get the encrypted text
    encrypted = bytes.fromhex(encrypted_b64)

    for i in range(0xffff):
        key = lfsr_stream(i, len(encrypted))
        plain = xor_bytes(encrypted, key)
        if b"TG20" in plain:
            print(f"[{i:02}] eureka: {plain}")
            break
        else:
            print(f"[{i:02}] searching..", end='\r')
            continue


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <hex-encoded-cipher>")
    else:
        main(sys.argv[1])
