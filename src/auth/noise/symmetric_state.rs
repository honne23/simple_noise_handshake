use super::{cipher, HASHLEN};
use sha2::{Digest, Sha256};

pub struct SymmetricState {
    ck: Vec<u8>,
    h: Vec<u8>,
    pub cipher_state: cipher::CipherState,
}

impl SymmetricState {
    pub fn new(protocol_name: &str) -> SymmetricState {
        let protocol_name_bytes = protocol_name.as_bytes();

        let h: Vec<u8> = if protocol_name_bytes.len() <= HASHLEN {
            let mut h_buf = [0u8; HASHLEN];
            for index in 0..protocol_name_bytes.len() {
                h_buf[index] = protocol_name_bytes[index];
            }
            h_buf.to_vec()
        } else {
            let mut hasher = Sha256::new();
            hasher.update(protocol_name_bytes);
            hasher.finalize_reset()[..].to_vec()
        };
        let ck = h.clone();
        SymmetricState {
            ck: ck,
            h: h,
            cipher_state: cipher::CipherState::new(),
        }
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h = hasher.finalize_reset()[..].to_vec();
    }

    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let (ck, temp_k, _) = cipher::hkdf(&self.ck, input_key_material, 2);
        self.ck = ck;
        self.cipher_state.initialise_key(&temp_k);
    }

    fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let (ck, temp_h, temp_k) = cipher::hkdf(&self.ck, input_key_material, 3);
        self.ck = ck;
        self.mix_hash(&temp_h);
        self.cipher_state.initialise_key(&temp_k.unwrap());
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = self.cipher_state.encrypt_with_ad(&self.h, plaintext);
        self.mix_hash(&cipher);
        cipher
    }

    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let plaintext = self.cipher_state.decrypt_with_ad(&self.h, ciphertext);
        self.mix_hash(ciphertext);
        plaintext
    }

    pub fn split(&self) -> (cipher::CipherState, cipher::CipherState) {
        let (temp_k1, temp_k2, _) = cipher::hkdf(&self.ck, &[], 2);
        let (mut c1, mut c2) = (cipher::CipherState::new(), cipher::CipherState::new());
        c1.initialise_key(&temp_k1);
        c2.initialise_key(&temp_k2);
        (c1, c2)
    }
}
