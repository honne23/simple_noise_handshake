use super::{cipher, HASHLEN};
use sha2::{Digest, Sha256};
use std::error::Error;
pub struct SymmetricState {
    ck: Vec<u8>,
    h: Vec<u8>,
    pub cipher_state: cipher::CipherState,
}

impl SymmetricState {
    /// Calls "Initialize" on the SymmetricState object defined in the protocol:
    /// [SymmetricState](https://noiseprotocol.org/noise.html#the-symmetricstate-object)
    pub fn new(protocol_name: &[u8]) -> SymmetricState {
        let h: Vec<u8> = if protocol_name.len() <= HASHLEN {
            let mut h_buf = [0u8; HASHLEN];
            for index in 0..protocol_name.len() {
                h_buf[index] = protocol_name[index];
            }
            h_buf.to_vec()
        } else {
            let mut hasher = Sha256::new();
            hasher.update(protocol_name);
            hasher.finalize_reset()[..].to_vec()
        };
        let ck = h.clone();
        SymmetricState {
            ck: ck,
            h: h,
            cipher_state: cipher::CipherState::new(),
        }
    }

    /// Calls "MixHash" on the SymmetricState object defined in the protocol:
    /// [SymmetricState](https://noiseprotocol.org/noise.html#the-symmetricstate-object)
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h = hasher.finalize_reset()[..].to_vec();
    }

    /// Calls "MixKey" on the SymmetricState object defined in the protocol:
    /// [SymmetricState](https://noiseprotocol.org/noise.html#the-symmetricstate-object)
    ///
    /// This function produces a new cipher key to feed into [cipher::CipherState] which it will use to decrypt and encrypt payloads.
    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let (ck, temp_k, _) = cipher::hkdf(&self.ck, input_key_material, 2);
        self.ck = ck;
        self.cipher_state.initialise_key(&temp_k);
    }

    /// Calls "MixKey" on the SymmetricState object defined in the protocol:
    /// [SymmetricState](https://noiseprotocol.org/noise.html#the-symmetricstate-object)
    ///
    /// NOTE: At the moment no protocols that support this have been implemented.
    fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let (ck, temp_h, temp_k) = cipher::hkdf(&self.ck, input_key_material, 3);
        self.ck = ck;
        self.mix_hash(&temp_h);
        self.cipher_state.initialise_key(&temp_k.unwrap());
    }

    /// Calls "EncryptAndHash" on the SymmetricState object defined in the protocol:
    /// [SymmetricState](https://noiseprotocol.org/noise.html#the-symmetricstate-object)
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = self.cipher_state.encrypt_with_ad(&self.h, plaintext);
        self.mix_hash(&cipher);
        cipher
    }

    /// Calls "DecryptAndHash" on the SymmetricState object defined in the protocol:
    /// [SymmetricState](https://noiseprotocol.org/noise.html#the-symmetricstate-object)
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let plaintext = self.cipher_state.decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Calls "Split" on the SymmetricState object defined in the protocol:
    /// [SymmetricState](https://noiseprotocol.org/noise.html#the-symmetricstate-object)
    pub fn split(&self) -> (cipher::CipherState, cipher::CipherState) {
        let (temp_k1, temp_k2, _) = cipher::hkdf(&self.ck, &[], 2);
        let (mut c1, mut c2) = (cipher::CipherState::new(), cipher::CipherState::new());
        c1.initialise_key(&temp_k1);
        c2.initialise_key(&temp_k2);
        (c1, c2)
    }
}
