pub mod multistream;
use std::{error::Error, net::SocketAddr};

use ed25519_dalek::Keypair;

use crate::auth::{HandShake, SecureChannel};
pub trait Connection {

    /// Connect to a remote peer using their [std::net::SocketAddr]
    fn connect(address: SocketAddr) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;

    /// Upgrade the connection to a [SecureChannel] for communication
    fn upgrade<'a, H: HandShake<'a, Self> + 'a>(
        connection: Self,
        peer_id: Keypair,
    ) -> Result<Box<dyn SecureChannel + 'a>, Box<dyn Error>>
    where
        Self: Sized + 'a;
}
