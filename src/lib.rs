#![feature(trait_alias)]
pub mod auth;
pub mod connection;
pub mod handshake {
    include!(concat!(env!("OUT_DIR"), "/handshake.rs"));
}
