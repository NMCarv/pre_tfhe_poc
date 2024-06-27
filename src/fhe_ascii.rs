use tfhe::prelude::*;
use tfhe::{ClientKey, FheUint8};

pub struct FheAsciiString {
    bytes: Vec<FheUint8>,
}

impl FheAsciiString {
    pub fn encrypt(string: &str, client_key: &ClientKey) -> Self {
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

    pub fn decrypt(&self, client_key: &ClientKey) -> String {
        let ascii_bytes: Vec<u8> = self
            .bytes
            .iter()
            .map(|fhe_b| fhe_b.decrypt(client_key))
            .collect();
        String::from_utf8(ascii_bytes).unwrap()
    }
}
