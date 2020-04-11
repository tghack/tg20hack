use super::copy_into_array;
use rand;

const SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

const FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

const CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

fn gen_iv() -> Vec<u8> {
    (0..16).map(|_| rand::random::<u8>()).collect()
}

fn xor_block(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn rotl32(v: u32, c: u8) -> u32 {
    v << c | v >> (32 - c)
}

fn non_linear_substitution(input: u32) -> u32 {
    let bytes: Vec<u8> = input
        .to_be_bytes()
        .iter()
        .map(|x| SBOX[*x as usize])
        .collect();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn linear_substitution(input: u32) -> u32 {
    input ^ rotl32(input, 2) ^ rotl32(input, 10) ^ rotl32(input, 18) ^ rotl32(input, 24)
}

fn linear_substitution_rk(input: u32) -> u32 {
    input ^ rotl32(input, 13) ^ rotl32(input, 23)
}

fn mixer_substitution_rk(input: u32) -> u32 {
    linear_substitution_rk(non_linear_substitution(input))
}

fn mixer_substitution(input: u32) -> u32 {
    linear_substitution(non_linear_substitution(input))
}

fn round_exchange(x0: u32, x1: u32, x2: u32, x3: u32, rk: u32) -> u32 {
    x0 ^ mixer_substitution(x1 ^ x2 ^ x3 ^ rk)
}

fn expand(key0: u32, key1: u32, key2: u32, key3: u32) -> Vec<u32> {
    let k = (key0 ^ FK[0], key1 ^ FK[1], key2 ^ FK[2], key3 ^ FK[3]);

    let rk0 = k.0 ^ mixer_substitution_rk(k.1 ^ k.2 ^ k.3 ^ CK[0]);
    let rk1 = k.1 ^ mixer_substitution_rk(k.2 ^ k.3 ^ rk0 ^ CK[1]);
    let rk2 = k.2 ^ mixer_substitution_rk(k.3 ^ rk0 ^ rk1 ^ CK[2]);
    let rk3 = k.3 ^ mixer_substitution_rk(rk0 ^ rk1 ^ rk2 ^ CK[3]);
    let rk4 = rk0 ^ mixer_substitution_rk(rk1 ^ rk2 ^ rk3 ^ CK[4]);
    let rk5 = rk1 ^ mixer_substitution_rk(rk2 ^ rk3 ^ rk4 ^ CK[5]);
    let rk6 = rk2 ^ mixer_substitution_rk(rk3 ^ rk4 ^ rk5 ^ CK[6]);
    let rk7 = rk3 ^ mixer_substitution_rk(rk4 ^ rk5 ^ rk6 ^ CK[7]);
    let rk8 = rk4 ^ mixer_substitution_rk(rk5 ^ rk6 ^ rk7 ^ CK[8]);
    let rk9 = rk5 ^ mixer_substitution_rk(rk6 ^ rk7 ^ rk8 ^ CK[9]);
    let rk10 = rk6 ^ mixer_substitution_rk(rk7 ^ rk8 ^ rk9 ^ CK[10]);
    let rk11 = rk7 ^ mixer_substitution_rk(rk8 ^ rk9 ^ rk10 ^ CK[11]);
    let rk12 = rk8 ^ mixer_substitution_rk(rk9 ^ rk10 ^ rk11 ^ CK[12]);
    let rk13 = rk9 ^ mixer_substitution_rk(rk10 ^ rk11 ^ rk12 ^ CK[13]);
    let rk14 = rk10 ^ mixer_substitution_rk(rk11 ^ rk12 ^ rk13 ^ CK[14]);
    let rk15 = rk11 ^ mixer_substitution_rk(rk12 ^ rk13 ^ rk14 ^ CK[15]);
    let rk16 = rk12 ^ mixer_substitution_rk(rk13 ^ rk14 ^ rk15 ^ CK[16]);
    let rk17 = rk13 ^ mixer_substitution_rk(rk14 ^ rk15 ^ rk16 ^ CK[17]);
    let rk18 = rk14 ^ mixer_substitution_rk(rk15 ^ rk16 ^ rk17 ^ CK[18]);
    let rk19 = rk15 ^ mixer_substitution_rk(rk16 ^ rk17 ^ rk18 ^ CK[19]);
    let rk20 = rk16 ^ mixer_substitution_rk(rk17 ^ rk18 ^ rk19 ^ CK[20]);
    let rk21 = rk17 ^ mixer_substitution_rk(rk18 ^ rk19 ^ rk20 ^ CK[21]);
    let rk22 = rk18 ^ mixer_substitution_rk(rk19 ^ rk20 ^ rk21 ^ CK[22]);
    let rk23 = rk19 ^ mixer_substitution_rk(rk20 ^ rk21 ^ rk22 ^ CK[23]);
    let rk24 = rk20 ^ mixer_substitution_rk(rk21 ^ rk22 ^ rk23 ^ CK[24]);
    let rk25 = rk21 ^ mixer_substitution_rk(rk22 ^ rk23 ^ rk24 ^ CK[25]);
    let rk26 = rk22 ^ mixer_substitution_rk(rk23 ^ rk24 ^ rk25 ^ CK[26]);
    let rk27 = rk23 ^ mixer_substitution_rk(rk24 ^ rk25 ^ rk26 ^ CK[27]);
    let rk28 = rk24 ^ mixer_substitution_rk(rk25 ^ rk26 ^ rk27 ^ CK[28]);
    let rk29 = rk25 ^ mixer_substitution_rk(rk26 ^ rk27 ^ rk28 ^ CK[29]);
    let rk30 = rk26 ^ mixer_substitution_rk(rk27 ^ rk28 ^ rk29 ^ CK[30]);
    let rk31 = rk27 ^ mixer_substitution_rk(rk28 ^ rk29 ^ rk30 ^ CK[31]);

    vec![
        rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, rk11, rk12, rk13, rk14, rk15, rk16,
        rk17, rk18, rk19, rk20, rk21, rk22, rk23, rk24, rk25, rk26, rk27, rk28, rk29, rk30, rk31,
    ]
}

fn encrypt(key: &[u8; 16], msg: &[u8]) -> Vec<u8> {
    let rk = expand(
        u32::from_be_bytes(copy_into_array(&key[0..4])),
        u32::from_be_bytes(copy_into_array(&key[4..8])),
        u32::from_be_bytes(copy_into_array(&key[8..12])),
        u32::from_be_bytes(copy_into_array(&key[12..16])),
    );

    let x0 = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]);
    let x1 = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    let x2 = u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]);
    let x3 = u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]);
    let x4 = round_exchange(x0, x1, x2, x3, rk[0]);
    let x5 = round_exchange(x1, x2, x3, x4, rk[1]);
    let x6 = round_exchange(x2, x3, x4, x5, rk[2]);
    let x7 = round_exchange(x3, x4, x5, x6, rk[3]);
    let x8 = round_exchange(x4, x5, x6, x7, rk[4]);
    let x9 = round_exchange(x5, x6, x7, x8, rk[5]);
    let x10 = round_exchange(x6, x7, x8, x9, rk[6]);
    let x11 = round_exchange(x7, x8, x9, x10, rk[7]);
    let x12 = round_exchange(x8, x9, x10, x11, rk[8]);
    let x13 = round_exchange(x9, x10, x11, x12, rk[9]);
    let x14 = round_exchange(x10, x11, x12, x13, rk[10]);
    let x15 = round_exchange(x11, x12, x13, x14, rk[11]);
    let x16 = round_exchange(x12, x13, x14, x15, rk[12]);
    let x17 = round_exchange(x13, x14, x15, x16, rk[13]);
    let x18 = round_exchange(x14, x15, x16, x17, rk[14]);
    let x19 = round_exchange(x15, x16, x17, x18, rk[15]);
    let x20 = round_exchange(x16, x17, x18, x19, rk[16]);
    let x21 = round_exchange(x17, x18, x19, x20, rk[17]);
    let x22 = round_exchange(x18, x19, x20, x21, rk[18]);
    let x23 = round_exchange(x19, x20, x21, x22, rk[19]);
    let x24 = round_exchange(x20, x21, x22, x23, rk[20]);
    let x25 = round_exchange(x21, x22, x23, x24, rk[21]);
    let x26 = round_exchange(x22, x23, x24, x25, rk[22]);
    let x27 = round_exchange(x23, x24, x25, x26, rk[23]);
    let x28 = round_exchange(x24, x25, x26, x27, rk[24]);
    let x29 = round_exchange(x25, x26, x27, x28, rk[25]);
    let x30 = round_exchange(x26, x27, x28, x29, rk[26]);
    let x31 = round_exchange(x27, x28, x29, x30, rk[27]);
    let x32 = round_exchange(x28, x29, x30, x31, rk[28]);
    let x33 = round_exchange(x29, x30, x31, x32, rk[29]);
    let x34 = round_exchange(x30, x31, x32, x33, rk[30]);
    let x35 = round_exchange(x31, x32, x33, x34, rk[31]);

    let y0 = u32::to_be_bytes(x35);
    let y1 = u32::to_be_bytes(x34);
    let y2 = u32::to_be_bytes(x33);
    let y3 = u32::to_be_bytes(x32);

    vec![
        y0[0], y0[1], y0[2], y0[3], y1[0], y1[1], y1[2], y1[3], y2[0], y2[1], y2[2], y2[3], y3[0],
        y3[1], y3[2], y3[3],
    ]
}

fn decrypt(key: &[u8; 16], msg: &[u8]) -> Vec<u8> {
    let rk = expand(
        u32::from_be_bytes(copy_into_array(&key[0..4])),
        u32::from_be_bytes(copy_into_array(&key[4..8])),
        u32::from_be_bytes(copy_into_array(&key[8..12])),
        u32::from_be_bytes(copy_into_array(&key[12..16])),
    );

    let x0 = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]);
    let x1 = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    let x2 = u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]);
    let x3 = u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]);
    let x4 = round_exchange(x0, x1, x2, x3, rk[31]);
    let x5 = round_exchange(x1, x2, x3, x4, rk[30]);
    let x6 = round_exchange(x2, x3, x4, x5, rk[29]);
    let x7 = round_exchange(x3, x4, x5, x6, rk[28]);
    let x8 = round_exchange(x4, x5, x6, x7, rk[27]);
    let x9 = round_exchange(x5, x6, x7, x8, rk[26]);
    let x10 = round_exchange(x6, x7, x8, x9, rk[25]);
    let x11 = round_exchange(x7, x8, x9, x10, rk[24]);
    let x12 = round_exchange(x8, x9, x10, x11, rk[23]);
    let x13 = round_exchange(x9, x10, x11, x12, rk[22]);
    let x14 = round_exchange(x10, x11, x12, x13, rk[21]);
    let x15 = round_exchange(x11, x12, x13, x14, rk[20]);
    let x16 = round_exchange(x12, x13, x14, x15, rk[19]);
    let x17 = round_exchange(x13, x14, x15, x16, rk[18]);
    let x18 = round_exchange(x14, x15, x16, x17, rk[17]);
    let x19 = round_exchange(x15, x16, x17, x18, rk[16]);
    let x20 = round_exchange(x16, x17, x18, x19, rk[15]);
    let x21 = round_exchange(x17, x18, x19, x20, rk[14]);
    let x22 = round_exchange(x18, x19, x20, x21, rk[13]);
    let x23 = round_exchange(x19, x20, x21, x22, rk[12]);
    let x24 = round_exchange(x20, x21, x22, x23, rk[11]);
    let x25 = round_exchange(x21, x22, x23, x24, rk[10]);
    let x26 = round_exchange(x22, x23, x24, x25, rk[9]);
    let x27 = round_exchange(x23, x24, x25, x26, rk[8]);
    let x28 = round_exchange(x24, x25, x26, x27, rk[7]);
    let x29 = round_exchange(x25, x26, x27, x28, rk[6]);
    let x30 = round_exchange(x26, x27, x28, x29, rk[5]);
    let x31 = round_exchange(x27, x28, x29, x30, rk[4]);
    let x32 = round_exchange(x28, x29, x30, x31, rk[3]);
    let x33 = round_exchange(x29, x30, x31, x32, rk[2]);
    let x34 = round_exchange(x30, x31, x32, x33, rk[1]);
    let x35 = round_exchange(x31, x32, x33, x34, rk[0]);

    let y0 = u32::to_be_bytes(x35);
    let y1 = u32::to_be_bytes(x34);
    let y2 = u32::to_be_bytes(x33);
    let y3 = u32::to_be_bytes(x32);

    vec![
        y0[0], y0[1], y0[2], y0[3], y1[0], y1[1], y1[2], y1[3], y2[0], y2[1], y2[2], y2[3], y3[0],
        y3[1], y3[2], y3[3],
    ]
}

pub fn ecb_encrypt(key: &[u8; 16], msg: &[u8]) -> Vec<u8> {
    let mut cipher = vec![];
    for chunk in msg.chunks(16) {
        if chunk.len() < 16 {
            // Pad up to 16 bytes
            let mut new_chunk = Vec::from(chunk);
            let pad_bytes = 16u8 - chunk.len() as u8;
            for _ in 0..pad_bytes {
                new_chunk.push(pad_bytes);
            }
            if new_chunk.len() != 16 {
                println!(
                    "Error; chunk is still not the right size: {}",
                    new_chunk.len()
                );
            }
            cipher.append(&mut encrypt(key, &new_chunk));
        } else {
            cipher.append(&mut encrypt(key, &chunk));
        }
    }
    cipher
}

pub fn cfb_encrypt(key: &[u8; 16], msg: &[u8]) -> Vec<u8> {
    let mut current = gen_iv();
    let mut cipher = current.clone();
    for chunk in msg.chunks(16) {
        // Pad up to 16 bytes
        if chunk.len() < 16 {
            let mut new_chunk = Vec::from(chunk);
            let pad_bytes = 16u8 - chunk.len() as u8;
            for _ in 0..pad_bytes {
                new_chunk.push(pad_bytes);
            }
            if new_chunk.len() != 16 {
                println!(
                    "Error; chunk is still not the right size: {}",
                    new_chunk.len()
                );
            }
            current = xor_block(&encrypt(key, &current), &new_chunk);
        // No need for padding
        } else {
            current = xor_block(&encrypt(key, &current), &chunk);
        }
        cipher.append(&mut current.clone());
    }

    cipher
}

pub fn ecb_decrypt(key: &[u8; 16], msg: &[u8]) -> Vec<u8> {
    let mut cipher = vec![];
    for chunk in msg.chunks_exact(16) {
        cipher.append(&mut decrypt(key, &chunk));
    }

    // Unpad
    if let Some(pad) = cipher.last() {
        let needle: Vec<u8> = (0..*pad).map(|_| *pad).collect();
        if cipher.ends_with(&needle) {
            cipher.truncate(cipher.len() - needle.len());
        }
    }

    cipher
}

pub fn cfb_decrypt(key: &[u8; 16], msg: &[u8]) -> Vec<u8> {
    let mut cipher = vec![];
    let mut chunks = msg.chunks_exact(16);
    let mut current = chunks
        .next()
        .expect("Message too short for decryption")
        .to_owned();

    // Decrypt
    for chunk in chunks {
        cipher.append(&mut xor_block(&encrypt(key, &current), chunk));
        current = chunk.to_vec();
    }

    // Unpad
    if let Some(pad) = cipher.last() {
        let needle: Vec<u8> = (0..*pad).map(|_| *pad).collect();
        if cipher.ends_with(&needle) {
            cipher.truncate(cipher.len() - needle.len());
        }
    }

    cipher
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rk() {
        let rk = expand(0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210);
        assert_eq!(rk[0], 0xf12186f9);
        assert_eq!(rk[1], 0x41662b61);
        assert_eq!(rk[2], 0x5a6ab19a);
        assert_eq!(rk[3], 0x7ba92077);
        assert_eq!(rk[4], 0x367360f4);
        assert_eq!(rk[5], 0x776a0c61);
        assert_eq!(rk[6], 0xb6bb89b3);
        assert_eq!(rk[7], 0x24763151);
        assert_eq!(rk[8], 0xa520307c);
        assert_eq!(rk[9], 0xb7584dbd);
        assert_eq!(rk[10], 0xc30753ed);
        assert_eq!(rk[11], 0x7ee55b57);
        assert_eq!(rk[12], 0x6988608c);
        assert_eq!(rk[13], 0x30d895b7);
        assert_eq!(rk[14], 0x44ba14af);
        assert_eq!(rk[15], 0x104495a1);
        assert_eq!(rk[16], 0xd120b428);
        assert_eq!(rk[17], 0x73b55fa3);
        assert_eq!(rk[18], 0xcc874966);
        assert_eq!(rk[19], 0x92244439);
        assert_eq!(rk[20], 0xe89e641f);
        assert_eq!(rk[21], 0x98ca015a);
        assert_eq!(rk[22], 0xc7159060);
        assert_eq!(rk[23], 0x99e1fd2e);
        assert_eq!(rk[24], 0xb79bd80c);
        assert_eq!(rk[25], 0x1d2115b0);
        assert_eq!(rk[26], 0x0e228aeb);
        assert_eq!(rk[27], 0xf1780c81);
        assert_eq!(rk[28], 0x428d3654);
        assert_eq!(rk[29], 0x62293496);
        assert_eq!(rk[30], 0x01cf72e5);
        assert_eq!(rk[31], 0x9124a012);
    }

    #[test]
    fn test_encrypt() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let msg = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let cipher = encrypt(&key, &msg);

        assert_eq!(
            cipher,
            [
                0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
                0x42, 0x46,
            ]
        );
    }

    #[test]
    fn test_ecb_encrypt() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let msg = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let cipher = ecb_encrypt(&key, &msg);

        assert_eq!(
            cipher,
            [
                0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
                0x42, 0x46,
            ]
        );
    }

    #[test]
    // This does not test the output of the encrypted block because it is
    // non-deterministic due to the usage of a randomly generated IV
    fn test_cfb_encrypt_len() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let msg = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let cipher = cfb_encrypt(&key, &msg);

        assert_eq!(cipher.len(), 32);
    }

    #[test]
    fn test_reencrypt() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut cipher = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        for _ in 0..1_000_000 {
            cipher = encrypt(&key, &cipher);
        }

        assert_eq!(
            cipher,
            [
                0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d,
                0x3f, 0x66,
            ]
        );
    }

    #[test]
    fn test_decrypt() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let cipher = vec![
            0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
            0x42, 0x46,
        ];
        let msg = decrypt(&key, &cipher);

        assert_eq!(
            msg,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10
            ]
        )
    }

    #[test]
    fn test_ecb_decrypt() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let cipher = vec![
            0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
            0x42, 0x46,
        ];
        let msg = ecb_decrypt(&key, &cipher);

        assert_eq!(
            msg,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10
            ]
        )
    }

    #[test]
    fn test_cfb_decrypt() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let cipher = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x27, 0x54, 0xb1, 0x0c, 0x80, 0x6a, 0xef, 0x23, 0x69, 0x89, 0x89, 0x88,
            0x2d, 0x80, 0x90, 0x3a,
        ];
        let msg = cfb_decrypt(&key, &cipher);

        assert_eq!(
            msg,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10
            ]
        )
    }

    #[test]
    fn test_redecrypt() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut cipher = vec![
            0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d,
            0x3f, 0x66,
        ];
        for _ in 0..1_000_000 {
            cipher = decrypt(&key, &cipher);
        }

        assert_eq!(
            cipher,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10
            ]
        )
    }

    #[test]
    fn test_ecb_encrypt_and_decrypt_no_pad() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let msg = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(ecb_decrypt(&key, &ecb_encrypt(&key, &msg)), msg);
    }

    #[test]
    fn test_ecb_encrypt_and_decrypt_with_pad() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let msg = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x55, 0x55, 0x55, 0x55, 0x66,
        ];
        assert_eq!(ecb_decrypt(&key, &ecb_encrypt(&key, &msg)), msg);
    }

    #[test]
    fn test_cfb_encrypt_and_decrypt_no_pad() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let msg = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(cfb_decrypt(&key, &cfb_encrypt(&key, &msg)), msg);
    }

    #[test]
    fn test_cfb_encrypt_and_decrypt_with_pad() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let msg = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x55, 0x55, 0x55, 0x55, 0x66,
        ];
        assert_eq!(cfb_decrypt(&key, &cfb_encrypt(&key, &msg)), msg);
    }
}
