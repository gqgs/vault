use cryptolib::blake2b::Blake2b;
use cryptolib::blake2s::Blake2s;
use cryptolib::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use cryptolib::hmac::Hmac;
use cryptolib::pbkdf2::pbkdf2;
use cryptolib::ripemd160::Ripemd160;
use cryptolib::sha2::{Sha256, Sha384, Sha512};
use cryptolib::sha3::{Sha3, Sha3Mode};
use cryptolib::{aes, blockmodes, buffer, chacha20, salsa20, symmetriccipher};
use rand::{thread_rng, RngCore};
use state::cipher::Cipher;
use state::hash::Hash;
use state::iterations::Iterations;

#[inline]
fn xor(v1: &[u8], v2: &[u8], res: &mut [u8]) {
    assert_eq!(v1.len(), v2.len());
    let len = v1.len();
    for i in 0..len {
        res[i] = v1[i] ^ v2[i];
    }
}

macro_rules! cipher {
    ($data:ident,$func:ident,$op:ident) => {{
        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new($data);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            let result = $func.$op(&mut read_buffer, &mut write_buffer, true)?;
            final_result.extend(
                write_buffer
                    .take_read_buffer()
                    .take_remaining()
                    .iter()
                    .map(|&i| i),
            );
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            }
        }
        Ok(final_result)
    }};
}

pub fn encrypt(
    cipher: Cipher,
    hash: Hash,
    iterations: Iterations,
    key: String,
    plaintext: &[u8],
) -> Result<([u8; 16], Vec<u8>), symmetriccipher::SymmetricCipherError> {
    let mut rng = thread_rng();
    let mut salt: [u8; 16] = [0; 16];
    let mut derived_key: [u8; 48] = [0; 48]; // 384bits

    rng.fill_bytes(&mut salt);
    hmac_digest_all(hash, key, &salt, iterations, &mut derived_key);

    let mut iv: [u8; 16] = [0; 16];
    xor(&salt, &derived_key[0..16], &mut iv);

    let key_slice = &derived_key[16..48];

    let mut encryptor = match cipher {
        Cipher::AESCBC => aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key_slice,
            &iv,
            blockmodes::PkcsPadding,
        ),
        Cipher::CHACHA20 => Box::new(chacha20::ChaCha20::new(key_slice, &iv[0..12])),
        Cipher::SALSA20 => Box::new(salsa20::Salsa20::new(key_slice, &iv[0..8])),
    };

    let ciphertext = cipher!(plaintext, encryptor, encrypt)?;
    Ok((salt, ciphertext))
}

pub fn decrypt(
    cipher: Cipher,
    hash: Hash,
    iterations: Iterations,
    key: String,
    data: Vec<u8>,
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut derived_key: [u8; 48] = [0; 48]; // 384bits
    assert!(data.len() > 16);
    let (salt, ciphertext) = data.split_at(16);

    hmac_digest_all(hash, key, salt, iterations, &mut derived_key);

    let mut iv: [u8; 16] = [0; 16];
    xor(&salt, &derived_key[0..16], &mut iv);

    let encrypted_text = &ciphertext[..];
    let key_slice = &derived_key[16..48];

    let mut decryptor = match cipher {
        Cipher::AESCBC => aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key_slice,
            &iv,
            blockmodes::PkcsPadding,
        ),
        Cipher::CHACHA20 => Box::new(chacha20::ChaCha20::new(key_slice, &iv[0..12])),
        Cipher::SALSA20 => Box::new(salsa20::Salsa20::new(key_slice, &iv[0..8])),
    };

    cipher!(encrypted_text, decryptor, decrypt)
}

macro_rules! hmac_digest {
    ($digest:expr,$key:ident,$salt:ident,$iter:ident,$derived_key:ident) => {{
        let mut hmac = Hmac::new($digest, $key.as_bytes());
        pbkdf2(&mut hmac, &$salt[..], $iter, $derived_key);
    }};
}

fn hmac_digest_all(
    hash: Hash,
    key: String,
    salt: &[u8],
    iterations: Iterations,
    derived_key: &mut [u8],
) {
    let iter = match iterations {
        Iterations::LOW => 10_000,
        Iterations::MEDIUM => 100_000,
        Iterations::HIGH => 1_000_000,
    };
    match hash {
        Hash::RIPEMD160 => hmac_digest!(Ripemd160::new(), key, salt, iter, derived_key),
        Hash::BLAKE2S => hmac_digest!(Blake2s::new(32), key, salt, iter, derived_key), // 256bits
        Hash::BLAKE2B => hmac_digest!(Blake2b::new(64), key, salt, iter, derived_key), // 512bits
        Hash::SHA2_256 => hmac_digest!(Sha256::new(), key, salt, iter, derived_key),
        Hash::SHA2_384 => hmac_digest!(Sha384::new(), key, salt, iter, derived_key),
        Hash::SHA2_512 => hmac_digest!(Sha512::new(), key, salt, iter, derived_key),
        Hash::SHA3_256 => hmac_digest!(Sha3::new(Sha3Mode::Sha3_256), key, salt, iter, derived_key),
        Hash::SHA3_384 => hmac_digest!(Sha3::new(Sha3Mode::Sha3_384), key, salt, iter, derived_key),
        Hash::SHA3_512 => hmac_digest!(Sha3::new(Sha3Mode::Sha3_512), key, salt, iter, derived_key),
    }
}
