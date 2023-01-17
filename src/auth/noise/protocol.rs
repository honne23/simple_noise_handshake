use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use prost::Message;

use crate::{
    auth::{noise::MessagePattern, HandShake, SecureChannel},
    connection::Connection,
    handshake,
};

use super::{
    cipher::CipherState,
    handshake_state::{HandshakeState, StaticKeypair},
};

use std::error::Error;

const SIGNATURE_PREFIX: &[u8; 24] = b"noise-libp2p-static-key:";


pub struct NoiseProtocol {}

pub struct NoiseChannel<'a, C: Connection> {
    encrypter: CipherState,
    decrypter: CipherState,
    reader: Box<dyn Fn(&mut C) -> Result<Vec<u8>, Box<dyn Error>> + 'a>,
    writer: Box<dyn Fn(&mut C, &[u8]) -> Result<(), Box<dyn Error>> + 'a>,
    connection: C,
}

impl<'a, C> HandShake<'a, C> for NoiseProtocol
where
    C: Connection,
{
    type Channel<'channel> = NoiseChannel<'channel, C>;

    fn upgrade<Reader, Writer>(
        connection: C,
        peer_id: Keypair,
        reader: Reader,
        writer: Writer,
    ) -> Result<Self::Channel<'a>, Box<dyn Error>>
    where
        C: Connection,
        Reader: Fn(&mut C) -> Result<Vec<u8>, Box<dyn Error>> + 'a,
        Writer: Fn(&mut C, &[u8]) -> Result<(), Box<dyn Error>> + 'a,
    {
        let mut connection = connection;
        let static_local = StaticKeypair::new();
        let mut hss = HandshakeState::new(true, &[], static_local, None, None, None);
        let init = hss.write_message(&[], vec![MessagePattern::E])?;
        writer(&mut connection, &init)?;

        // Stage 2: <- e, ee, s, es
        let encrypted_response = reader(&mut connection)?;
        let decrypted_response = hss.read_message(
            &encrypted_response,
            vec![
                MessagePattern::E,
                MessagePattern::Ee,
                MessagePattern::S,
                MessagePattern::Es,
            ],
        )?;
        let result: handshake::NoiseHandshakePayload =
            handshake::NoiseHandshakePayload::decode(&decrypted_response[..]).unwrap();

        // Verify sig
        // Get remote PeerID
        let key_proto = handshake::PublicKey::decode(&result.identity_key.unwrap()[..]).unwrap();
        let remote_id = PublicKey::from_bytes(&key_proto.data).unwrap();

        // Get remote static noise key
        let remote_static = hss.rs.as_ref().unwrap().as_bytes();
        let message = [&SIGNATURE_PREFIX[..], &remote_static[..]].concat();

        // Get signature:
        let signature = Signature::from_bytes(&result.identity_sig.unwrap()).unwrap();
        // message is remote static key
        remote_id.verify(&message, &signature)?;

        // Stage 3
        let auth_payload = Self::auth_payload(peer_id, hss.s.clone())?;
        let encrypted_payload =
            hss.write_message(&auth_payload, vec![MessagePattern::S, MessagePattern::Se])?;
        writer(&mut connection, &encrypted_payload)?;

        let (encrypter, decrypter) = hss.finalize();
        Ok(NoiseChannel {
            encrypter,
            decrypter,
            connection,
            reader: Box::new(reader),
            writer: Box::new(writer),
        })
    }
}

impl<'a, C: Connection> SecureChannel for NoiseChannel<'a, C> {
    fn read(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Get noise message
        let encrypted_data = (self.reader)(&mut self.connection)?;
        // Decrypt noise message
        self.decrypter.decrypt_with_ad(&[], &encrypted_data)
    }

    fn write(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let encrypted_data = self.encrypter.encrypt_with_ad(&[], data)?;
        (self.writer)(&mut self.connection, &encrypted_data)?;
        Ok(())
    }
}

impl NoiseProtocol {
    fn auth_payload(
        keypair: Keypair,
        noise_static_key: StaticKeypair,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        // Create payloads to be serialized
        let mut payload = handshake::NoiseHandshakePayload::default();

        // Add the PeerID to the HandshakePayload
        let key_payload = handshake::PublicKey { r#type: 1, data: keypair.public.as_bytes().to_vec() };
        let mut buf = vec![];
        key_payload.encode(&mut buf)?;
        payload.identity_key = Some(buf);

        // Add local signature to payload
        let data = [&SIGNATURE_PREFIX[..], &noise_static_key.0.as_bytes()[..]].concat();
        let signature = keypair.sign(&data).to_bytes().to_vec();
        payload.identity_sig = Some(signature);

        let mut buf = vec![];
        payload.encode(&mut buf)?;
        Ok(buf)
    }
}
