use crypto;
use editor;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;

use self::cipher::Cipher;
use self::hash::Hash;
use self::iterations::Iterations;
use self::kdf::KDF;

pub mod cipher;
pub mod hash;
pub mod iterations;
pub mod kdf;

#[derive(Default)]
pub struct State {
    hash: Hash,
    cipher: Cipher,
    iterations: Iterations,
    kdf: KDF,
}

pub enum Action {
    // key, plaintext, path
    Encrypt(String, String, std::path::PathBuf),
    // key, ciphertext
    Decrypt(String, Vec<u8>),
}

#[derive(Copy, Clone)]
pub enum UpdateMsg {
    Hash(Hash),
    Cipher(Cipher),
    Iterations(Iterations),
    KDF(KDF),
}

impl State {
    pub fn new() -> State {
        Default::default()
    }

    fn set_hash(&mut self, hash: Hash) {
        self.hash = hash;
    }

    fn set_cipher(&mut self, cipher: Cipher) {
        self.cipher = cipher;
    }

    fn set_iterations(&mut self, iterations: Iterations) {
        self.iterations = iterations;
    }

    fn set_kdf(&mut self, kdf: KDF) {
        self.kdf = kdf;
    }

    pub fn update(&mut self, updatemsg: UpdateMsg) {
        match updatemsg {
            UpdateMsg::Hash(hash) => self.set_hash(hash),
            UpdateMsg::Cipher(cipher) => self.set_cipher(cipher),
            UpdateMsg::Iterations(iterations) => self.set_iterations(iterations),
            UpdateMsg::KDF(kdf) => self.set_kdf(kdf),
        }
    }

    pub fn action(&self, action: Action) -> Option<editor::Action> {
        match action {
            Action::Encrypt(key, plaintext, path) => {
                match crypto::encrypt(
                    self.cipher,
                    self.hash,
                    self.iterations,
                    self.kdf,
                    key,
                    &plaintext.into_bytes(),
                ) {
                    Ok((salt, ciphertext)) => {
                        let mut file = match File::create(&path) {
                            Err(err) => panic!("Error creating file {}: {}", path.display(), err),
                            Ok(file) => file,
                        };

                        match file.write(&salt) {
                            Err(err) => panic!("Error writing to file {}: {}", path.display(), err),
                            Ok(file) => file,
                        };

                        match file.write(&ciphertext) {
                            Err(err) => panic!("Error writing to file {}: {}", path.display(), err),
                            Ok(file) => file,
                        };
                    }
                    Err(_) => panic!("Error encrypting file {}", path.display()),
                };
                None
            }
            Action::Decrypt(key, content) => {
                if let Ok(plain_utf8) = crypto::decrypt(
                    self.cipher,
                    self.hash,
                    self.iterations,
                    self.kdf,
                    key,
                    content,
                ) {
                    if let Ok(plaintext) = String::from_utf8(plain_utf8) {
                        return Some(editor::Action::UpdateTextView(plaintext));
                    }
                }
                None
            }
        }
    }
}

pub trait Updater {
    fn update(&self) -> UpdateMsg;
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kdf {
            KDF::ARGON2 => write!(f, "{} | {} | {}", self.cipher, self.iterations, self.kdf),
            _ => write!(
                f,
                "{} | {} | {} | {}",
                self.cipher, self.hash, self.iterations, self.kdf
            ),
        }
    }
}
