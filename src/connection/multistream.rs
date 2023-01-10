use std::{
    error::Error,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
};
use unsigned_varint::{decode, encode};

use crate::auth::{HandShake, SecureChannel};
use ed25519_dalek::Keypair;

use super::Connection;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MultistreamError {
    #[error("peer does not accept /multistream/1.0.0 connections")]
    Negotiation(),
    #[error("the peer does not support the /noise handshake")]
    Auth(),
}

pub struct Multistream {
    stream: TcpStream,
}

impl Connection for Multistream {
    fn connect(address: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(address)?;
        let mut connection = Self::new(stream);
        connection.write(b"/multistream/1.0.0\n", false)?;
        let received = connection.read(false)?;
        let received = Self::deserialize(&received)?;
        if std::str::from_utf8(&received)? != "/multistream/1.0.0" {
            return Err(MultistreamError::Negotiation().into());
        }

        connection.write(b"/noise\n", false)?;
        let received = connection.read(false)?;
        let received = Self::deserialize(&received)?;
        if std::str::from_utf8(&received)? != "/noise" {
            return Err(MultistreamError::Auth().into());
        }
        Ok(connection)
    }

    fn upgrade<'a, H: HandShake<'a, Self> + 'a>(
        connection: Self,
        peer_id: Keypair,
    ) -> Result<Box<dyn SecureChannel + 'a>, Box<dyn Error>>
    where
        Self: Sized + 'a,
    {
        let reader = |x: &mut Multistream| -> Result<Vec<u8>, Box<dyn Error>> { Ok(x.read(true)?) };

        let writer = |x: &mut Multistream, data: &[u8]| -> Result<(), Box<dyn Error>> {
            x.write(data, true)?;
            Ok(())
        };
        Ok(Box::new(H::upgrade(connection, peer_id, reader, writer)?))
    }
}

impl Multistream {
    pub fn new(stream: TcpStream) -> Self {
        Multistream { stream: stream }
    }
    fn write(&mut self, message: &[u8], secure: bool) -> Result<(), Box<dyn Error>> {
        if secure {
            let data_len = (message.len() as u16).to_be_bytes();
            let payload = [&data_len[..], &message[..]].concat();
            self.stream.write_all(&payload)?;
            self.stream.flush()?;
            Ok(())
        } else {
            let msg = Self::serialize(message);
            self.stream.write_all(&msg)?;
            self.stream.flush()?;
            Ok(())
        }
    }

    fn read(&mut self, secure: bool) -> Result<Vec<u8>, Box<dyn Error>> {
        if secure {
            let mut msg_len = [0u8; 2];
            self.stream.read(&mut msg_len)?;
            let proto_len = u16::from_be_bytes(msg_len);
            let mut encrypted = vec![0u8; proto_len.into()];
            self.stream.read(&mut encrypted)?;
            Ok(encrypted)
        } else {
            let mut reader = BufReader::new(self.stream.try_clone()?);
            let mut line = String::new();
            reader.read_line(&mut line)?;
            Ok(line.as_bytes().to_vec())
        }
    }

    pub fn serialize(message: &[u8]) -> Vec<u8> {
        let mut buf = encode::usize_buffer();
        let encoded_size = encode::usize(message.len(), &mut buf);
        [encoded_size, message].concat()
    }
    
    pub fn deserialize(message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let (_, buf) = decode::usize(message)?;
        Ok(buf[..buf.len() - 1].to_vec())
    }
}

