use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

use super::HASHLEN;

pub type CipherKey = Vec<u8>;

pub struct CipherState {
    pub k: Option<CipherKey>, //32 bytes
    n: u64,                   //unsigned int nonce
}

impl CipherState {
    pub fn new() -> Self {
        CipherState { k: None, n: 0 }
    }

    pub fn initialise_key(&mut self, k: &[u8]) {
        self.k = Some(k.to_vec());
        self.n = 0;
    }

    fn set_nonce(&mut self, nonce: u64) {
        self.n = nonce;
    }

    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    fn get_current_nonce(&self) -> Nonce {
        let nb: [u8; 8] = self.n.to_le_bytes();
        let mut nonce: [u8; 12] = [0; 12];
        for index in 4..12 {
            nonce[index] = nb[index - 4];
        }
        Nonce::from(nonce)
    }

    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let key = self.k.as_ref();
        if let Some(k) = key {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(k));
            let result = cipher
                .encrypt(
                    &self.get_current_nonce(),
                    Payload {
                        msg: plaintext,
                        aad: ad,
                    },
                )
                .unwrap();
            self.n += 1;
            return result;
        } else {
            return plaintext.to_vec();
        }
    }

    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let key = self.k.as_ref();
        if let Some(k) = key {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(k));
            let result = cipher
                .decrypt(
                    &self.get_current_nonce(),
                    Payload {
                        msg: ciphertext,
                        aad: ad,
                    },
                )
                .unwrap();
            self.n += 1;
            return result;
        } else {
            return ciphertext.to_vec();
        }
    }
    /*
    pub fn rekey(&mut self) {
        let key = ChaCha20Poly1305::generate_key(&mut chaRng);
        let cipher = ChaCha20Poly1305::new(&key);
        self.k = Some(cipher);
    }
     */
}

pub fn hkdf(
    chaining_key: &[u8],
    input_key_material: &[u8],
    num_outputs: usize,
) -> (Vec<u8>, Vec<u8>, Option<Vec<u8>>) {
    // Derive temp key
    let mut mac = <HmacSha256 as Mac>::new_from_slice(chaining_key).unwrap();
    mac.update(input_key_material);
    let temp_key = mac.finalize_reset().into_bytes();

    // Compute hkdf from temp key
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&temp_key).unwrap();
    mac.update(&[1u8]);
    let output1 = mac.finalize_reset().into_bytes();
    let in2 = [&output1[..], &[2u8][..]].concat();
    mac.update(&in2);
    let output2 = mac.finalize_reset().into_bytes();
    if num_outputs == 2 {
        (output1.to_vec(), output2.to_vec(), None)
    } else {
        let in3 = [&output2[..], &[3u8][..]].concat();
        mac.update(&in3);
        let output3 = mac.finalize_reset().into_bytes();
        (output1.to_vec(), output2.to_vec(), Some(output3.to_vec()))
    }
}

pub fn dh_static(local_private: &StaticSecret, remote_public: &PublicKey) -> Vec<u8> {
    local_private
        .diffie_hellman(remote_public)
        .as_bytes()
        .to_vec()
}
