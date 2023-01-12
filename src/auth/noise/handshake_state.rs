//use ecies_ed25519 as ecs;
use super::cipher;
use super::symmetric_state::SymmetricState;
use super::{MessagePattern, DHLEN};
use std::error::Error;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use thiserror::Error;

const PROTOCOL_NAME: &'static [u8; 32] = b"Noise_XX_25519_ChaChaPoly_SHA256";

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("the message pattern prvided was unsuported")]
    MessagePatternUnsupported(),
}

#[derive(Clone)]
pub struct StaticKeypair(pub PublicKey, pub StaticSecret);

type EphemeralKeypair = (PublicKey, StaticSecret); // x25519-lib reccomends using static for both secrets when using Noise

impl StaticKeypair {
    pub fn new() -> Self {
        let secret = StaticSecret::new(OsRng);
        let public = PublicKey::from(&secret);
        StaticKeypair(public, secret)
    }
}

pub struct HandshakeState {
    initiator: bool,
    symmetric_state: SymmetricState,

    pub s: StaticKeypair, // local static
    pub rs: Option<PublicKey>,
    e: Option<EphemeralKeypair>, // local ephemeral
    re: Option<PublicKey>,
}

impl HandshakeState {
    /// Calls "Initialize" from the the HandshakeState noise protocol specification:
    ///
    /// See [Initialize](https://noiseprotocol.org/noise.html#the-handshakestate-object)
    pub fn new(
        initiator: bool,
        prologue: &[u8],
        s: StaticKeypair,
        e: Option<EphemeralKeypair>,
        rs: Option<PublicKey>,
        re: Option<PublicKey>,
    ) -> HandshakeState {
        let mut sym_state = SymmetricState::new(PROTOCOL_NAME);
        sym_state.mix_hash(prologue);
        HandshakeState {
            s: s,
            e: e,
            rs: rs,
            re: re,
            initiator: initiator,
            symmetric_state: sym_state,
        }
    }

    /// Calls "WriteMessage" from the the HandshakeState noise protocol specification:
    ///
    /// See [WriteMessage](https://noiseprotocol.org/noise.html#the-handshakestate-object)
    pub fn write_message(&mut self, payload: &[u8], patterns: Vec<MessagePattern>) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buffer: Vec<u8> = Vec::new();
        for pattern in patterns {
            match pattern {
                MessagePattern::E => {
                    let secret = StaticSecret::new(OsRng);
                    let public = PublicKey::from(&secret);
                    self.e = Some((public, secret));
                    let public_bytes = public.as_bytes().to_vec();
                    let mut buf_bytes = public_bytes.clone();
                    buffer.append(&mut buf_bytes);
                    self.symmetric_state.mix_hash(&public_bytes);
                }
                MessagePattern::Ee => {
                    self.symmetric_state.mix_key(&cipher::dh_static(
                        &self.e.as_ref().unwrap().1,
                        &self.re.unwrap(),
                    ));
                }
                MessagePattern::Es => {
                    if self.initiator {
                        self.symmetric_state.mix_key(&cipher::dh_static(
                            &self.e.as_ref().unwrap().1,
                            &self.rs.unwrap(),
                        ));
                    } else {
                        self.symmetric_state
                            .mix_key(&cipher::dh_static(&self.s.1, &self.re.unwrap()));
                    }
                }
                MessagePattern::S => {
                    let mut payload = self.symmetric_state.encrypt_and_hash(self.s.0.as_bytes())?;
                    buffer.append(&mut payload);
                }
                MessagePattern::Se => {
                    if self.initiator {
                        self.symmetric_state
                            .mix_key(&cipher::dh_static(&self.s.1, &self.re.unwrap()));
                    } else {
                        self.symmetric_state.mix_key(&cipher::dh_static(
                            &self.e.as_ref().unwrap().1,
                            &self.rs.unwrap(),
                        ));
                    }
                }
                _ => return Err(HandshakeError::MessagePatternUnsupported().into()),
            }
        }

        let mut encrypted = self.symmetric_state.encrypt_and_hash(payload)?;
        buffer.append(&mut encrypted);
        Ok(buffer)
    }

    /// Calls "ReadMessage" from the the HandshakeState noise protocol specification:
    ///
    /// [ReadMessage](https://noiseprotocol.org/noise.html#the-handshakestate-object)
    pub fn read_message(&mut self, received: &[u8], patterns: Vec<MessagePattern>) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut received = received.to_vec();
        for pattern in patterns {
            match pattern {
                MessagePattern::E => {
                    let mut remote_public = [0u8; DHLEN];
                    received[..DHLEN]
                        .iter()
                        .enumerate()
                        .for_each(|(index, val)| {
                            remote_public[index] = *val;
                        });
                    let public = PublicKey::from(remote_public);
                    self.re = Some(public);
                    self.symmetric_state.mix_hash(&remote_public);
                    received.drain(..DHLEN);
                }
                MessagePattern::Ee => {
                    self.symmetric_state.mix_key(&cipher::dh_static(
                        &self.e.as_ref().unwrap().1,
                        &self.re.unwrap(),
                    ));
                }
                MessagePattern::S => {
                    let has_key = self.symmetric_state.cipher_state.has_key();
                    let window = if has_key { ..DHLEN + 16 } else { ..DHLEN };
                    let temp = &received[window];
                    let mut remote_static_bytes: [u8; DHLEN] = [0; DHLEN];
                    let payload = self.symmetric_state
                        .decrypt_and_hash(temp)?
                        .iter()
                        .enumerate()
                        .for_each(|(index, val)| {
                            remote_static_bytes[index] = *val;
                        });
                    self.rs = Some(PublicKey::from(remote_static_bytes));
                    received.drain(window);
                }
                MessagePattern::Es => {
                    if self.initiator {
                        self.symmetric_state.mix_key(&cipher::dh_static(
                            &self.e.as_ref().unwrap().1,
                            &self.rs.unwrap(),
                        ));
                    } else {
                        self.symmetric_state
                            .mix_key(&cipher::dh_static(&self.s.1, &self.re.unwrap()));
                    }
                }
                MessagePattern::Se => {
                    if self.initiator {
                        self.symmetric_state
                            .mix_key(&cipher::dh_static(&self.s.1, &self.re.unwrap()));
                    } else {
                        self.symmetric_state.mix_key(&cipher::dh_static(
                            &self.e.as_ref().unwrap().1,
                            &self.rs.unwrap(),
                        ));
                    }
                }
                _ => return Err(HandshakeError::MessagePatternUnsupported().into())
            }
        }
        self.symmetric_state.decrypt_and_hash(&received)
    }

    /// A helper function used to produce two [cipher::CipherState] which encrypt and decrypt messages on the transport.
    pub fn finalize(&self) -> (cipher::CipherState, cipher::CipherState) {
        self.symmetric_state.split()
    }
}
