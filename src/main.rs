mod fhe_ascii;

use crate::fhe_ascii::FheAsciiString;
use recrypt::{
    api::{EncryptedValue, Plaintext},
    prelude::*,
};
use std::error::Error;
use std::time::Instant;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder};

fn pad_vec(mut vec: Vec<u8>, target_length: usize, pad_byte: u8) -> Vec<u8> {
    if vec.len() < target_length {
        vec.resize(target_length, pad_byte);
    }
    vec
}

fn main() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();

    // 1. Initialize recrypt and generate keypairs
    let system = Recrypt::new();
    let (_alice_priv, alice_pub) = system.generate_key_pair().unwrap();
    let (bob_priv, bob_pub) = system.generate_key_pair().unwrap();
    let (charlie_priv, charlie_pub) = system.generate_key_pair().unwrap();
    let signing_keypair = system.generate_ed25519_key_pair();

    let elapsed = start.elapsed();
    println!(
        "[Took {:.2?} secs] Generated keypairs for Alice, Bob, and Charlie",
        elapsed
    );

    // 2. Alice has raw data
    let alice_data = "Secret message from Alice";
    println!("Alice's raw data: {:?}", alice_data);

    // 3. Alice generates TFHE-rs key to encrypt raw data
    let start = Instant::now();
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);
    let elapsed = start.elapsed();
    println!("[Took {:.2?} secs] Generated TFHE-rs keys", elapsed);

    // Encrypt Alice's data with TFHE
    let start = Instant::now();
    let encrypted_data = FheAsciiString::encrypt(alice_data, &client_key);
    let elapsed = start.elapsed();
    println!(
        "[Took {:.2?} secs] Encrypted Alice's data with TFHE",
        elapsed
    );

    // 4. Alice encrypts TFHE-rs key with Bob's public key
    let start = Instant::now();
    let serialized_client_key = bincode::serialize(&client_key)?;

    // Split the serialized key into chunks that fit into Plaintext
    let chunk_size = 384; // Plaintext::ENCODED_SIZE_BYTES
    let key_chunks: Vec<Plaintext> = serialized_client_key
        .chunks(chunk_size)
        .map(|chunk| {
            let padded_chunk = pad_vec(chunk.to_vec(), chunk_size, 0);
            Plaintext::new_from_slice(&padded_chunk).unwrap()
        })
        .collect();

    let encrypted_chunks_for_bob: Vec<EncryptedValue> = key_chunks
        .iter()
        .map(|chunk| system.encrypt(chunk, &bob_pub, &signing_keypair).unwrap())
        .collect();

    let _encrypted_chunks_for_alice: Vec<EncryptedValue> = key_chunks
        .iter()
        .map(|chunk| system.encrypt(chunk, &alice_pub, &signing_keypair).unwrap())
        .collect();

    let elapsed = start.elapsed();
    println!("[Took {:.2?} secs] Encrypted TFHE key for Bob", elapsed);

    // 5. Bob decrypts data
    let start = Instant::now();
    let decrypted_chunks: Vec<Plaintext> = encrypted_chunks_for_bob
        .iter()
        .map(|chunk| system.decrypt(chunk.clone(), &bob_priv).unwrap())
        .collect();

    let decrypted_tfhe_key: Vec<u8> = decrypted_chunks
        .into_iter()
        .flat_map(|chunk| chunk.bytes().to_vec())
        .collect();

    let bob_tfhe_key: ClientKey = bincode::deserialize(&decrypted_tfhe_key)?;
    let bob_decrypted_data = encrypted_data.decrypt(&bob_tfhe_key);
    let elapsed = start.elapsed();

    println!(
        "[Took {:.2?} secs] Bob decrypted data: {:?}",
        elapsed, bob_decrypted_data
    );

    // 6. Bob generates a re-encryption key for Charlie
    let start = Instant::now();
    let re_encryption_key = system
        .generate_transform_key(&bob_priv, &charlie_pub, &signing_keypair)
        .unwrap();
    let elapsed = start.elapsed();
    println!(
        "[Took {:.2?} secs] Bob generated re-encryption key for Charlie",
        elapsed
    );

    // 7. TFHE-rs key gets re-encrypted
    let start = Instant::now();
    let encrypted_chunks_for_charlie: Vec<EncryptedValue> = encrypted_chunks_for_bob
        .iter()
        .map(|chunk| {
            system
                .transform(chunk.clone(), re_encryption_key.clone(), &signing_keypair)
                .unwrap()
        })
        .collect();
    let elapsed = start.elapsed();
    println!(
        "[Took {:.2?} secs] Re-encrypted TFHE key for Charlie",
        elapsed
    );

    // 8. Charlie decrypts data
    let start = Instant::now();
    let charlie_decrypted_chunks: Vec<Plaintext> = encrypted_chunks_for_charlie
        .iter()
        .map(|chunk| system.decrypt(chunk.clone(), &charlie_priv).unwrap())
        .collect();

    let charlie_decrypted_tfhe_key: Vec<u8> = charlie_decrypted_chunks
        .into_iter()
        .flat_map(|chunk| chunk.bytes().to_vec())
        .collect();

    let charlie_tfhe_key: ClientKey = bincode::deserialize(&charlie_decrypted_tfhe_key)?;
    let charlie_decrypted_data = encrypted_data.decrypt(&charlie_tfhe_key);
    let elapsed = start.elapsed();

    println!(
        "[Took {:.2?} secs] Charlie decrypted data: {:?}",
        elapsed, charlie_decrypted_data
    );

    Ok(())
}
