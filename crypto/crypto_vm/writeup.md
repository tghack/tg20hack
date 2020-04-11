# Writeup [Crypto VM](./README.md)

## Task description
**Author: Kakekongen**

**Difficulty: challenging**

**Category: crypto**

While infiltrating a computer system belonging to a high value target, we
managed to exfiltrate a possibly interesting virtual machine.

We also captured the network traffic while it was running, but we are
unable to determine the content of the message being sent. It looks
encrypted.

If you are able to help us decipher the message, it could be of great importance.

## Files:
- [network capture](uploads/capture.pcapng)
- [vm binary](uploads/vm)
- [vm bytecode](uploads/dummy_encrypt_flag.assembly.out)

---

## Writeup
We are provided with a VM binary that can execute the provided VM bytecode.
By running it and reversing it, we discover that it will encrypt some data in the
bytecode and send the encrypted data hex-encoded over raw TCP to a host.

In addition to the VM binary and the VM bytecode, we also have a network capture
that contains the encrypted data sent over TCP.

Further reversing of the VM shows us that the bytecode builds up a number of
instructions that will be used for encrypting the data.
It will then get two bytes of entropy and use that as a seed to the encryption
engine initially programmed.
Afterwards it will load data and decrypt it before sending it to the encryption
engine and actually encrypting the loaded data, which is the flag.
Finally, the VM will load a hostname and port before sending the encrypted
flag to the target server hex-encoded.

When reversing the instructions programming the encryption engine, we can
determine that it implements a
[Xorshift LFSR](https://en.wikipedia.org/wiki/Linear-feedback_shift_register#Xorshift_LFSRs)
that is seeded with 16 bits of entropy, meaning we can brute force the
entropy and decrypt the encrypted flag we can extract from the network capture.

A proof-of-concept of cracking the cipher can be found in the [poc.py](./src/poc.py)
script file, which will crack the cipher provided as a hex-encoded string.

Yielding the flag: `TG20{virtual_machines_can_be_notoriously_difficult_to_reverse}`.
