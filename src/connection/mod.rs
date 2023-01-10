pub mod multistream;
use std::{error::Error, net::SocketAddr};

use ed25519_dalek::Keypair;
use libp2p::core::connection;

use crate::auth::{HandShake, SecureChannel};
pub trait Connection {
    fn connect(address: SocketAddr) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;

    fn upgrade<'a, H: HandShake<'a, Self> + 'a>(
        connection: Self,
        peer_id: Keypair,
    ) -> Result<Box<dyn SecureChannel + 'a>, Box<dyn Error>>
    where
        Self: Sized + 'a;
}
