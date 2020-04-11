# Writeup [Post Quantum Crypto](./README.md)

## Task description
**Author: Kakekongen**

**Difficulty: challenging**

**Category: crypto**

There have been a few breakthroughs on quantum computing here on the ship, so we
are in need of post quantum crypto to be prepared. We hired some people
from Norway to create it for us, but we have reasons to believe they messed up...
Here's their client for the flag retrieval in addition to a network dump.
Can you crack the encryption and retrieve the flag?

## Files:
- [exchange](uploads/conversation.pcapng)
- [client.py](uploads/client.py)

---

## Writeup
We are provided with a (fictitious) client for a client to securely transfer a symmetric
key over the network, and using that symmetric key to encrypt the flag.
In addition to the client, we also have a network dump of the key exchange and the
encrypted flag being sent over the network.

By analyzing the source code, we see that the client generates random bytes, requests
the public key from the server and uses that public key to
[encapsulate the key](https://en.wikipedia.org/wiki/Key_encapsulation) for secure
key exchange with the server.

From the network dump, we can extract the public key sent by the server to the client,
the encapsulated key sent back to the server, and the encrypted flag.

The number of PQ ciphers (in particular for KEM) submitted to the
[NIST PQ crypto competition](https://csrc.nist.gov/Projects/post-quantum-cryptography)
is not great, and the challenge text hints toward the cipher being Norwegian will reduce
the number of candidate ciphers to a single one, namely
[Edon K](https://pqcryptohub.com/Algorithms/EdonKDescription/) by Danilo Gligoroski and
Kristian Gjosteen of NTNU.

By researching the cipher, we should be able to discover the fact that is was one of the
ciphers being (horribly) broken during the first round, with a published
[cracking script](https://groups.google.com/a/list.nist.gov/forum/#!topic/pqc-forum/sQuZCcHL1bU)
by a pair of cryptographers of [Inria](https://www.inria.fr/en).

We can utilize this script to crack the KEM and recover the secret before using the
secret to decrypt the ciphertext extracted from the network dump.

Putting all this together, we can create a [cracking script](./crack.py) that will
crack the KEM and use the recovered secret to decrypt the flag.

Yielding the flag: `TG20{post_quantum_crypto_is_not_necessarily_safe}`.
