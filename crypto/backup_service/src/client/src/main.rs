use blake2::{Blake2b, Digest};
use rand::{RngCore, SeedableRng};
use rand_hc;
use reqwest;
use reqwest::StatusCode;
use structopt::StructOpt;

use std::convert::AsMut;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::time::SystemTime;

#[allow(dead_code)]
mod sm4;

#[derive(Debug, StructOpt)]
#[structopt(name = "Backup client", about = "Client for backing up to a server")]
enum Cli {
    /// Store the contents of `file_name` at the backup `server` for later restoration.
    Store { server: String, file_name: String },
    /// Retrieve and restore a previously stored file from the `server`
    /// encrypted using the `key`.
    Restore {
        server: String,

        key: String,

        #[structopt(parse(from_str))]
        output: Option<PathBuf>,
    },
}

fn copy_into_array<A, T>(slice: &[T]) -> A
where
    A: Default + AsMut<[T]>,
    T: Copy,
{
    let mut a = A::default();
    <A as AsMut<[T]>>::as_mut(&mut a).copy_from_slice(slice);
    a
}

fn get_sym_key(keyword: &str) -> [u8; 16] {
    let mut rng = rand_hc::Hc128Rng::from_seed(copy_into_array(&keyword.as_bytes()));
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);
    key
}

fn get_random_u128(r: &mut rand::rngs::StdRng) -> u128 {
    let v: Vec<u8> = [r.next_u64().to_be_bytes(), r.next_u64().to_be_bytes()]
        .iter()
        .flat_map(|x| x.iter().map(|x| *x))
        .collect();
    u128::from_be_bytes(copy_into_array(&v))
}

// Generate 16 bytes of randomness
fn gen_sym_key() -> ([u8; 16], String) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Unable to generate symmetric key");

    // Do something rad - try and mix in randomness, but in such a way that the randomness is
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
    (get_sym_key(&keyword), keyword)
}

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    // Parse CLI
    // - store {filename} => generates key, hashes key, sends encrypted file to server and prints key
    // - restore {key} => hashes key, requests the encrypted file, decrypts the file and saves it
    match Cli::from_args() {
        Cli::Store { server, file_name } => {
            // Open and read file
            if let Ok(mut file) = File::open(&file_name) {
                let mut contents = String::new();
                if let Ok(_) = file.read_to_string(&mut contents) {
                    // Get symmetric key and hash it
                    let (key, keyword) = gen_sym_key();
                    let mut hasher = Blake2b::new();
                    hasher.input(&key);
                    let hash = hasher.result();

                    // Send the file
                    let url = format!("{}/store/{:x}", &server, &hash);
                    println!("Storing at: {}", url);
                    if let Ok(url) = reqwest::Url::parse(&url) {
                        // Post the file contents to the server for storage
                        let client = reqwest::Client::new();
                        let body = client
                            .post(url)
                            .body(sm4::cfb_encrypt(&key, contents.as_bytes()))
                            .send()
                            .await?;
                        // Report key only if we successfully backed up the file
                        if body.status() == StatusCode::OK {
                            println!("Stored {} with the key \"{}\"", &file_name, &keyword);
                        } else {
                            println!("Failed to store {}", &file_name);
                        }
                    } else {
                        println!("Unable to parse provided server address to a URL");
                    }
                } else {
                    println!("Unable to read file to string");
                }
            } else {
                println!("Unable to open the specified file");
            }
        }
        Cli::Restore {
            server,
            key,
            output,
        } => {
            // Hash the provided key to get the correct file path
            let mut hasher = Blake2b::new();
            hasher.input(get_sym_key(&key));

            // Fetch the encrypted file
            let url = format!("{}/restore/{:x}", &server, hasher.result());
            println!("Requesting: {}", url);
            if let Ok(url) = reqwest::Url::parse(&url) {
                let body = reqwest::get(url).await?;

                // Report file if we successfully restored it using our key
                if body.status() == StatusCode::OK {
                    let file = body.bytes().await?;
                    let decrypted_file = sm4::cfb_decrypt(&get_sym_key(&key), &file);
                    if let Ok(decrypted_file) = String::from_utf8(decrypted_file) {
                        if let Some(output) = output {
                            if let Ok(mut file) = File::create(&output) {
                                match file.write_all(decrypted_file.as_bytes()) {
                                    Ok(_) => println!("We successfully restored the backup with key \"{}\" and wrote it to file {:?}", &key, output.to_str().expect("Filename contains non-UTF8 strings")),
                                    Err(e) =>
                                        println!("We were unable to write the restored backup to file {}: {}", output.to_str().expect("Filename contains non-UTF-8 strings"), e)
                                }
                            }
                        } else {
                            println!(
                                "We successfully restored the backup with key \"{}\": {}",
                                &key, decrypted_file
                            );
                        }
                    } else {
                        println!("Unable to convert file back to text");
                    }
                } else {
                    println!(
                        "[STATUS: {:?}] Failed to restore a file with key \"{}\"",
                        body.status(),
                        &key
                    );
                }
            } else {
                println!("Unable to parse provided server address to a URL");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    // Generate 16 bytes of randomness
    fn test_gen_sym_key() {
        let nows: Vec<Duration> = [
            1580162621539722892,
            1580161612936974194,
            1580161612933202361,
            1580161612374978960,
            1580161612373130971,
            1580161611789472561,
            1580161611785628690,
            1580161610019937036,
            1580161610018080478,
            1580161606967744897,
        ]
        .iter()
        .map(|x| Duration::from_secs(*x))
        .collect();
        let keys: Vec<[u8; 16]> = [
            "8c28c1892b19f572ecbc5447b0a63abc",
            "728129a33e18f572ecbc55529a4e9342",
            "b90f6fa33e18f572ecbc55529a081d89",
            "903fa9803e18f572ecbc5552b9ce2da0",
            "dbf0cd803e18f572ecbc5552b9aae2eb",
            "311d93ef3e18f572ecbc5552d6f40f01",
            "1262c8ef3e18f572ecbc5552d6af7022",
            "0c150a753f18f572ecbc55534c6d073c",
            "dec82e753f18f572ecbc55534c49daee",
            "8157fdce3f18f572ecbc5553f79a45b1",
        ]
        .iter()
        .map(|x| get_sym_key(x))
        .collect();

        fn calculate_sym_key(k: &Duration) -> [u8; 16] {
            // Do something rad - try and mix in randomness, but in such a way that the randomness is
            // cancelled out, and we in reality only really depend on the timestamp
            let mut r = rand::rngs::StdRng::from_entropy();
            let a = get_random_u128(&mut r);
            let b = get_random_u128(&mut r);
            let c = get_random_u128(&mut r);
            let d = get_random_u128(&mut r);

            let keyword = format!(
                "{:016x}{:016x}",
                ((k.as_secs() as u128
                    ^ a
                    ^ 0x3f078547c65552e3f10c39f874bc24cd
                    ^ c
                    ^ 0x399a919fbae9d0d6913147eea826537f
                    ^ a
                    ^ 0x78a692c6a06853eb0725bab51562f9b2
                    ^ c) as u64)
                    .swap_bytes(),
                (k.as_secs() as u128
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

        let a: Vec<[u8; 16]> = nows.iter().map(|x| calculate_sym_key(x)).collect();
        assert_eq!(a, keys);
    }
}
