use rand::Rng;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint8};

// Simplified PRE structure (placeholder for actual NAL16 implementation)
struct PRE {
    // This would contain the actual PRE implementation
}

impl PRE {
    fn setup() -> Self {
        // Initialize PRE system
        PRE {}
    }

    fn keygen(&self) -> (Vec<u8>, Vec<u8>) {
        // Generate a key pair
        let mut rng = rand::thread_rng();
        let pub_key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let priv_key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        (pub_key, priv_key)
    }

    fn encrypt(&self, pub_key: &[u8], data: &[u8]) -> Vec<u8> {
        // Encrypt data with public key (simplified)
        data.iter()
            .zip(pub_key.iter().cycle())
            .map(|(&d, &k)| d ^ k)
            .collect()
    }

    fn decrypt(&self, priv_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        // Decrypt data with private key (simplified)
        ciphertext
            .iter()
            .zip(priv_key.iter().cycle())
            .map(|(&c, &k)| c ^ k)
            .collect()
    }

    fn generate_re_encryption_key(&self, from_priv: &[u8], to_pub: &[u8]) -> Vec<u8> {
        // Generate re-encryption key (simplified)
        from_priv
            .iter()
            .zip(to_pub.iter())
            .map(|(&f, &t)| f ^ t)
            .collect()
    }

    fn re_encrypt(&self, re_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        // Re-encrypt ciphertext (simplified)
        ciphertext
            .iter()
            .zip(re_key.iter().cycle())
            .map(|(&c, &k)| c ^ k)
            .collect()
    }
}

pub const UP_LOW_DISTANCE: u8 = 32;

struct FheAsciiString {
    bytes: Vec<FheUint8>,
}

impl FheAsciiString {
    fn encrypt(string: &str, client_key: &ClientKey) -> Self {
        assert!(
            string.chars().all(|char| char.is_ascii()),
            "The input string must only contain ascii letters"
        );

        let fhe_bytes: Vec<FheUint8> = string
            .bytes()
            .map(|b| FheUint8::encrypt(b, client_key))
            .collect();

        Self { bytes: fhe_bytes }
    }

    fn decrypt(&self, client_key: &ClientKey) -> String {
        let ascii_bytes: Vec<u8> = self
            .bytes
            .iter()
            .map(|fhe_b| fhe_b.decrypt(client_key))
            .collect();
        String::from_utf8(ascii_bytes).unwrap()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate PRE-compatible keypairs
    let pre = PRE::setup();
    let (alice_pub, _alice_priv) = pre.keygen();
    let (bob_pub, bob_priv) = pre.keygen();
    let (charlie_pub, charlie_priv) = pre.keygen();

    println!("Generated keypairs for Alice, Bob, and Charlie");

    // 2. Alice has raw data
    let alice_data = "Secret message from Alice";
    println!("Alice's raw data: {:?}", alice_data);

    // 3. Alice generates TFHE-rs key to encrypt raw data
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    // Encrypt Alice's data with TFHE
    let encrypted_data = FheAsciiString::encrypt(alice_data, &client_key);

    println!("Encrypted Alice's data with TFHE");

    // 4. Alice encrypts TFHE-rs key with Bob's public key and hers
    let serialized_tfhe_key = bincode::serialize(&client_key)?;
    let encrypted_tfhe_key_for_bob = pre.encrypt(&bob_pub, &serialized_tfhe_key);
    let _encrypted_tfhe_key_for_alice = pre.encrypt(&alice_pub, &serialized_tfhe_key);

    println!("Encrypted TFHE key for Bob and Alice");

    // 5. Bob decrypts data
    let decrypted_tfhe_key = pre.decrypt(&bob_priv, &encrypted_tfhe_key_for_bob);
    let bob_tfhe_key: ClientKey = bincode::deserialize(&decrypted_tfhe_key)?;

    let bob_decrypted_data = encrypted_data.decrypt(&bob_tfhe_key);

    println!("Bob decrypted data: {:?}", bob_decrypted_data);

    // 6. Bob generates a re-encryption key for Charlie
    let re_encryption_key = pre.generate_re_encryption_key(&bob_priv, &charlie_pub);

    // 7. TFHE-rs key gets re-encrypted
    let re_encrypted_tfhe_key = pre.re_encrypt(&re_encryption_key, &encrypted_tfhe_key_for_bob);

    // 8. Charlie decrypts data
    let charlie_decrypted_tfhe_key = pre.decrypt(&charlie_priv, &re_encrypted_tfhe_key);
    let charlie_tfhe_key: ClientKey = bincode::deserialize(&charlie_decrypted_tfhe_key)?;

    let charlie_decrypted_data = encrypted_data.decrypt(&charlie_tfhe_key);

    println!("Charlie decrypted data: {:?}", charlie_decrypted_data);

    Ok(())
}
