use ed25519_dalek::Keypair;

use crate::connection::Connection;
use std::error::Error;
pub mod noise;

pub enum AuthProtocol {
    Noise,
}
impl AuthProtocol {
    pub fn name(&self) -> &[u8] {
        match *self {
            AuthProtocol::Noise => b"/noise\n"
        }
    }
}

pub trait HandShake<'a, C: Connection> {
    /// Channel lifetime is tied to the lifetime of the Connection
    type Channel<'channel>: SecureChannel;

    /// Upgrade a connection into a secure channel, this method takes ownershup of the connection
    /// so the raw connection can never be used to communicate.
    /// [`Reader`] is a function that takes a connection and reads content from the underlying stream.
    /// [`Writer`] is a function that takes a connection and and some encrypted content and write it to the underlying stream.
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
    /// A function that allows a secure channel to securely write to the underlying stream.
    fn write(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>>;

    /// A function that allows a secure channel to read securely from the underlying stream.
    fn read(&mut self) -> Result<Vec<u8>, Box<dyn Error>>;
}
