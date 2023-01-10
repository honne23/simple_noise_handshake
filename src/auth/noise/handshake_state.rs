//use ecies_ed25519 as ecs;
use super::cipher;
use super::symmetric_state::SymmetricState;
use super::{MessagePattern, DHLEN};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

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

    pub s: StaticKeypair,        // local static
    e: Option<EphemeralKeypair>, // local ephemeral
    pub rs: Option<PublicKey>,
    re: Option<PublicKey>,
}

impl HandshakeState {
    // handshake pattern always XX
    pub fn new(
        initiator: bool,
        prologue: &[u8],
        s: StaticKeypair,
        e: Option<EphemeralKeypair>,
        rs: Option<PublicKey>,
        re: Option<PublicKey>,
    ) -> HandshakeState {
        let mut sym_state = SymmetricState::new("Noise_XX_25519_ChaChaPoly_SHA256");
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

    // only the messages relevant for the XX communication are implemented
    pub fn write_message(&mut self, payload: &[u8], patterns: Vec<MessagePattern>) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        patterns.iter().for_each(|pattern| match pattern {
            MessagePattern::e => {
                let secret = StaticSecret::new(OsRng);
                let public = PublicKey::from(&secret);
                self.e = Some((public, secret));
                let public_bytes = public.as_bytes().to_vec();
                let mut buf_bytes = public_bytes.clone();
                buffer.append(&mut buf_bytes);
                self.symmetric_state.mix_hash(&public_bytes);
            }
            MessagePattern::ee => {
                self.symmetric_state.mix_key(&cipher::dh_static(
                    &self.e.as_ref().unwrap().1,
                    &self.re.unwrap(),
                ));
            }
            MessagePattern::es => {
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
            MessagePattern::s => {
                let mut payload = self.symmetric_state.encrypt_and_hash(self.s.0.as_bytes());
                buffer.append(&mut payload)
            }
            MessagePattern::se => {
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
            _ => return,
        });

        let mut encrypted = self.symmetric_state.encrypt_and_hash(payload);
        buffer.append(&mut encrypted);
        buffer
    }

    pub fn read_message(&mut self, received: &[u8], patterns: Vec<MessagePattern>) -> Vec<u8> {
        let mut received = received.to_vec();
        patterns.iter().for_each(|pattern| {
            match *pattern {
                MessagePattern::e => {
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
                MessagePattern::ee => {
                    self.symmetric_state.mix_key(&cipher::dh_static(
                        &self.e.as_ref().unwrap().1,
                        &self.re.unwrap(),
                    ));
                }
                MessagePattern::s => {
                    let has_key = self.symmetric_state.cipher_state.has_key();
                    let window = if has_key { ..DHLEN + 16 } else { ..DHLEN };
                    let temp = &received[window];
                    let mut remote_static_bytes: [u8; DHLEN] = [0; DHLEN];
                    self.symmetric_state
                        .decrypt_and_hash(temp)
                        .iter()
                        .enumerate()
                        .for_each(|(index, val)| {
                            remote_static_bytes[index] = *val;
                        });
                    self.rs = Some(PublicKey::from(remote_static_bytes));
                    received.drain(window);
                }
                MessagePattern::es => {
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
                MessagePattern::se => {
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
                _ => return,
            };
        });
        self.symmetric_state.decrypt_and_hash(&received)
    }

    pub fn finalize(&self) -> (cipher::CipherState, cipher::CipherState) {
        self.symmetric_state.split()
    }
}
