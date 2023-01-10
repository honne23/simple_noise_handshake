use ed25519_dalek::Keypair;

use crate::connection::Connection;
use std::error::Error;
pub mod noise;

pub trait HandShake<'a, C: Connection> {
    type Channel<'channel>: SecureChannel;

    fn upgrade<Reader, Writer>(
        connection: C,
        peer_id: Keypair,
        reader: Reader,
        writer: Writer,
    ) -> Result<Self::Channel<'a>, Box<dyn Error>>
    where
        C: Connection,
        Reader: Fn(&mut C) -> Result<Vec<u8>, Box<dyn Error>> + 'a,
        Writer: Fn(&mut C, &[u8]) -> Result<(), Box<dyn Error>> + 'a;
}

pub trait SecureChannel {
    fn write(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>>;

    fn read(&mut self) -> Result<Vec<u8>, Box<dyn Error>>;
}
