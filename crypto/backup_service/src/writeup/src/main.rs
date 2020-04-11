use blake2::{Blake2b, Digest};
use num_cpus;
use rand::{RngCore, SeedableRng};
use rand_hc;
use structopt::StructOpt;

use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::SystemTime;

#[allow(dead_code)]
mod sm4;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Cracking cipher",
    about = "Client for cracking the cipher backed up"
)]
struct Cli {
    known_hash: String,

    #[structopt(parse(from_str))]
    enc_file: Option<PathBuf>,
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

fn gen_sym_key(now: u128) -> ([u8; 16], String) {
    // We don't have to do anything crazy
    let keyword = format!(
        "{:016x}{:016x}",
        ((now
            ^ 0x3f078547c65552e3f10c39f874bc24cd
            ^ 0x399a919fbae9d0d6913147eea826537f
            ^ 0x78a692c6a06853eb0725bab51562f9b2) as u64)
            .swap_bytes(),
        (now ^ 0x81461e79565cb438b424196f309e7f02
            ^ 0x54a24c9738f59478372064e7c9a15054
            ^ 0x6f16b582a3971d017a55f44709a0b366) as u64
    );

    (get_sym_key(&keyword), keyword)
}

fn do_work(
    known_hash: String,
    start_secs: u64,
    work_num: usize,
    tot_threads: usize,
    loc_pair: Arc<(Mutex<String>, Condvar)>,
) {
    let (lock, cvar) = &*loc_pair;
    let now = SystemTime::now();
    for i in (0..start_secs + work_num as u64).rev().step_by(tot_threads) {
        let (key, keyword) = gen_sym_key(i as u128);
        let mut hasher = Blake2b::new();
        hasher.input(&key);
        let hash = format!("{:x}", hasher.result());
        if i % 10000 < tot_threads as u64 {
            let completed = lock.lock().expect("Unable to lock mutex");
            if *completed != "" {
                return;
            } else if work_num == 0 {
                let per_sec = (start_secs - i) as f64
                    / now.elapsed().expect("Unable to get elapsed time").as_secs() as f64;
                println!("Number of tries per second: {:.2}", per_sec);
            }
        }
        if hash == known_hash {
            println!("Got the correct hash {:?} from keyword {}", hash, keyword);
            let mut completed = lock.lock().expect("Unable to lock mutex");
            *completed = keyword;
            cvar.notify_one();
            return;
        }
    }
}

fn main() {
    let cli = Cli::from_args();
    let start_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Unable to generate symmetric key")
        .as_secs();

    let pair = Arc::new((Mutex::new(String::new()), Condvar::new()));
    let num_threads = num_cpus::get();

    // Spawn threads for cracking the timestamp
    let mut handles = vec![];
    for i in 0..num_threads {
        let hash = cli.known_hash.clone();
        let loc_pair = pair.clone();
        handles.push(thread::spawn(move || {
            do_work(hash, start_secs.clone(), i, num_threads, loc_pair)
        }));
    }

    // Wait for the keyword to be cracked
    let keyword;
    let (lock, cvar) = &*pair;
    {
        let mut started = lock.lock().unwrap();
        while *started == "" {
            started = cvar.wait(started).unwrap();
        }
        keyword = (*started).to_string();
    }

    // Wait for all threads to exit
    for h in handles {
        h.join().expect("Unable to join child");
    }

    // Read encrypted file, decrypt it and print
    if let Some(enc_file) = cli.enc_file {
        if let Ok(mut file) = File::open(enc_file) {
            let mut contents = Vec::new();
            if let Ok(_) = file.read_to_end(&mut contents) {
                let decrypted_file = sm4::cfb_decrypt(&get_sym_key(&keyword), &contents);
                if let Ok(decrypted_file) = String::from_utf8(decrypted_file) {
                    println!("Decrypted file contents: {}", decrypted_file);
                }
            }
        }
    // If file not provided, simply report keyword for retrieval with client
    } else {
        println!("Cracked keyword: {}", keyword);
    }
}
