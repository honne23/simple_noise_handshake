use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use hmac::{Hmac, Mac};
use std::error::Error;

type HmacSha256 = Hmac<Sha256>;

pub type CipherKey = Vec<u8>;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("could not decrypt payload")]
    DecyrptionFail(),
}


/// An implementation of the [`CipherState`] object from the noise protocol.
///
/// See [CipherState](https://noiseprotocol.org/noise.html#the-cipherstate-object)
pub struct CipherState {
    pub k: Option<CipherKey>, //32 bytes
    n: u64,                   //unsigned int nonce
}

impl CipherState {
    /// A helper function that fufills the role of `InitializeKey(empty)` from the noise spec.
    ///
    /// See [InitializeKey](https://noiseprotocol.org/noise.html#the-cipherstate-object)
    pub fn new() -> Self {
        CipherState { k: None, n: 0 }
    }

    /// A function that calls `InitializeKey(key)` on the `CipherState` object defined in the protocol.
    ///
    /// See [InitializeKey](https://noiseprotocol.org/noise.html#the-cipherstate-object)
    pub fn initialise_key(&mut self, k: &[u8]) {
        self.k = Some(k.to_vec());
        self.n = 0;
    }

    /// A function that calls `SetNonce` on the `CipherState` object defined in the protocol.
    ///
    /// See [SetNonce](https://noiseprotocol.org/noise.html#the-cipherstate-object)
    fn set_nonce(&mut self, nonce: u64) {
        self.n = nonce;
    }

    /// A function that calls `HasKey` on the `CipherState` object defined in the protocol.
    /// Used to verify the existence of a key publicly.
    ///  
    /// See [HasKey](https://noiseprotocol.org/noise.html#the-cipherstate-object)
    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    /// A helper function that constructs the 96 bit nonce used in the [chacha20poly1305::ChaCha20Poly1305] cipher.
    fn get_current_nonce(&self) -> Nonce {
        let nb: [u8; 8] = self.n.to_le_bytes();
        let mut nonce: [u8; 12] = [0; 12];
        for index in 4..12 {
            nonce[index] = nb[index - 4];
        }
        Nonce::from(nonce)
    }

    /// A function that calls `EncryptWithAd` on the `CipherState` object defined in the protocol.
    /// Auto-increments the nonce value.
    ///  
    /// See [EncryptWithAd](https://noiseprotocol.org/noise.html#the-cipherstate-object)
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

    /// A function that calls `EncryptWithAd` on the `CipherState` object defined in the protocol.
    /// Auto increments the nonce value.
    ///
    /// See [CipherState](https://noiseprotocol.org/noise.html#the-cipherstate-object)
    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let key = self.k.as_ref();
        if let Some(k) = key {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(k));
            let result = match cipher
                .decrypt(
                    &self.get_current_nonce(),
                    Payload {
                        msg: ciphertext,
                        aad: ad,
                    },
                ) {
                    Ok(content) => content,
                    Err(_) => return Err(CipherError::DecyrptionFail().into())
                };
            self.n += 1;
            Ok(result)
        } else {
            return Ok(ciphertext.to_vec())
        }
    }

    /// Skeleta implementation of `Rekey()` from the spec.
    /// Libp2p does not support `Rekey` as part of their connection specification.
    ///
    /// See the libp2p connection spec [here](https://github.com/libp2p/specs/tree/master/connections).
    /// See the libp2p noise spec [here](https://github.com/libp2p/specs/blob/master/noise/README.md).
    pub fn rekey(&mut self) {
        todo!()
    }
}

/// Implementation of the HKDF function specified in the noise protocol.
///
/// See [HKDF()](https://noiseprotocol.org/noise.html#hash-functions)
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

/// Implements the [x25519_dalek] `dh` function specified as part of the noise protocol.
///
/// See [DH()](https://noiseprotocol.org/noise.html#dh-functions)
pub fn dh_static(local_private: &StaticSecret, remote_public: &PublicKey) -> Vec<u8> {
    local_private
        .diffie_hellman(remote_public)
        .as_bytes()
        .to_vec()
}
