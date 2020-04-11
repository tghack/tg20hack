# Writeup [Backup Service](./README.md)

## Task description
**Author: Kakekongen**

**Difficulty: crazy**

**Category: crypto**

One of our infrastructure engineers came over some peculiar traffic containing
encrypted data. We suspect someone was exfiltrating data out of our network.
She quickly managed to locate the machine sending the data but she was not able
to determine the names or content of the files being sent over the network.

She did manage to get the binary being run before it got deleted.
We have information suggesting a previously discovered binary acting as a server
might be involved in this.

We trust you to determine what data might be exfiltrated from our network.

## Files:
- [network capture](uploads/capture.pcapng)
- [client](uploads/client)
- [server](uploads/server)
---

## Writeup
This final crypto challenge presents us with two binaries; a client and a server.
The client is for performing backup and restoring it at a later point, and the
server is accepting the backup files and allowing a client to query for them
at a later time.

Only the client has knowledge of the key, and the server only sees a hash
and the encrypted file contents.
This is the same information we have as provided by the network capture file.

To solve this, we need to reverse engineer the client. Reverse engineering the
client will show that when storing a file for backup, it generates a key, uses
that key to encrypt the file, hashes the key using
[Blake2b][1] and sending the encrypted file to the backup server using the key
hash as part of the request path.

That way, a store request will be of the form:
```
POST /store/<hashed_key>

<encrypted_content>
```

Further reverse engineering will show that the key is generated according to
the following algorithm:

```rust
fn get_sym_key(keyword: &str) -> [u8; 16] {
    let mut rng = rand_hc::Hc128Rng::from_seed(copy_into_array(&keyword.as_bytes()));
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);
    key
}

fn gen_key() -> (String) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)

    // Mix in randomness, but in such a way that the randomness is
    // cancelled out, and we in reality only really depend on the timestamp
    let mut r = rand::rngs::StdRng::from_entropy();
    let a = get_random_u128(&mut r);
    let b = get_random_u128(&mut r);
    let c = get_random_u128(&mut r);
    let d = get_random_u128(&mut r);

    let keyword = format!(
        "{:016x}{:016x}",
        ((now.as_secs() as u128
            ^ a
            ^ 0x3f078547c65552e3f10c39f874bc24cd
            ^ c
            ^ 0x399a919fbae9d0d6913147eea826537f
            ^ a
            ^ 0x78a692c6a06853eb0725bab51562f9b2
            ^ c) as u64)
            .swap_bytes(),
        (now.as_secs() as u128
            ^ b
            ^ 0x81461e79565cb438b424196f309e7f02
            ^ d
            ^ 0x54a24c9738f59478372064e7c9a15054
            ^ b
            ^ 0x6f16b582a3971d017a55f44709a0b366
            ^ d) as u64
    );
    get_sym_key(&keyword)
}
```

Where the random u128 bytes cancel each other out and will not provide any more
entropy to the key generation, and the constants can be combined beforehand.
This can then be simplified to the following:

```rust
fn get_sym_key(keyword: &str) -> [u8; 16] {
    let mut rng = rand_hc::Hc128Rng::from_seed(copy_into_array(&keyword.as_bytes()));
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);
    key
}

fn gen_key() -> (String) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u128;

    let keyword = format!(
        "{:016x}{:016x}",
        ((now ^ 0x7e3b861edcd4d1de6718c4a3c9f88e00) as u64)
            .swap_bytes(),
        (now ^ 0xbaf2e76ccd3e3d41f95189cff09f9c30) as u64
    );
    get_sym_key(&keyword)
}
```

This shows us that the only entropy source of the key is the current system time
since epoch in seconds.

From the reverse engineering knowledge of the key being hashed and used for the
request path, we can construct an oracle for determining when we have found the
correct key:

```rust
if hash(&current_key) == known_key_hash {
    println!("Key: {:?} matches the known key hash", &current_key);
}
```

This can be put together to iterate over the timestamps (from the current time
and back toward 0), generate the key, hash it an compare it to the known key hash:

```rust
fn get_sym_key(keyword: &str) -> [u8; 16] {
    let mut rng = rand_hc::Hc128Rng::from_seed(copy_into_array(&keyword.as_bytes()));
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);
    key
}

fn gen_key(now: u128) -> (String) {
    let keyword = format!(
        "{:016x}{:016x}",
        ((now ^ 0x7e3b861edcd4d1de6718c4a3c9f88e00) as u64)
            .swap_bytes(),
        (now ^ 0xbaf2e76ccd3e3d41f95189cff09f9c30) as u64
    );
    get_sym_key(&keyword)
}

fn crack_key(known_key_hash: &str) -> u128 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u128;
    for i in (0..now).rev() {
        if hash(&gen_key(i)) == known_key_hash {
            println!("Timestamp {} yields the correct hash", i);
            i
        }
    }
    u128::max_value()
}
```

Now that we have cracked the encryption key, we need to reverse the encryption
algorithm. By looking at the way the blocks are encrypted and combined, we can
quickly determine that it is using [CFB mode][2] to encrypt the data.
If we search the binary for known crypto constants we are able to determine that
the encryption scheme is using a [S-box][3] from the Chinese cipher [SM4][4].

With this knowledge, we can extract the encrypted file from the body of the
[POST request][5] and use that to decrypt the encrypted file extracted from
the network capture.

Because the network capture contains a number of files, we need to extract
and decrypt all of them, with their own separate cracked key.

All these stages are combined in the [POC file](src/writeup/src/main.rs).

After decrypting the correct file, we get the flag:

`TG20{reversing_crypto_can_be_difficult_and_it_is_very_important_to_generate_keys_with_enough_entropy}`

[1]: https://en.wikipedia.org/wiki/BLAKE_%28hash_function%29#BLAKE2b_algorithm
[2]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_(CFB)
[3]: https://en.wikipedia.org/wiki/S-box
[4]: https://en.wikipedia.org/wiki/SM4_(cipher)
[5]: https://en.wikipedia.org/wiki/POST_(HTTP)
