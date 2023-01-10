# Simple noise handshake
This repository supplies a simplified implementation of the `Noise` handshake such that it only supports the `XX` handshake compatible with libp2p nodes (such as those on the `IPFS` network).

`Connections` are generic objects that can manage an underlying byte stream over the network. The `Multistream` connection has been implemented for the purposes of this repository.

`HandShakes` represent the logic for authentication handshakes that can take place over the network to secure a connection. This repository only allows you to `read` and `write` from a `SecureChannel`.


## Entrypoint
See `tests/` for examples on the usage of the library.

## Traits
Library defines the following traits to implement `Connection`s and `HandShake`s:

```rust
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
```

```rust
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
```

## Testing
## Peer list
Known working peers (testedt):
- 147.75.84.175:4001 (Web3 Storage) https://github.com/web3-storage/web3.storage/blob/main/PEERS
- 139.178.88.145:4001 (Web3 Storage)
- 5.161.92.43:4001 (StorJ) https://docs.ipfs.tech/how-to/peering-with-content-providers/#content-provider-list


### All Tests:
```bash
cargo test
```
### All tests with debug output
```bash
cargo test -- -nocapture
```

### Only integration test and override default remote peer
```bash
export PEER_ADDR="139.178.88.145:4001"
cargo test --package noise_handshake --test noise_handshake_integration -- noise::test_handshake --exact --nocapture
```


## TODO
- The `CipherState` implemention is barebones and likely lacks quite a few security checks (such as bounds on the `Nonces`)
- At the moment there is no implementation for `async Connections`, these could straightforwardly be support by the `TokioTcpStream` as opposed to the `std::net::TcpStream` in use now.
- Multiplexing is not implemented correctly outside of the integration test, support for `Yamux` and more general multiplexing should be developed
- There are alot of `heap` allocations throughout, the hot-paths can likely be optimised to work more directly with slice references, it would be best to review this after implementing `async Connections`  to ensure we don't run into borrower semantics indirectly.



## Peering sources
1. https://docs.ipfs.tech/how-to/peering-with-content-providers/#content-provider-list
2. https://github.com/web3-storage/web3.storage/blob/main/PEERS


## References
1. https://ipfs.io/ipfs/QmR7GSQM93Cx5eAg6a6yRzNde1FQv7uL6X1o4k7zrJa3LX/ipfs.draft3.pdf
2. https://github.com/libp2p/specs/blob/master/connections/README.md
3. https://github.com/libp2p/specs/blob/master/noise/README.md
4. https://noiseprotocol.org/noise.html
5. https://github.com/mcginty/snow
6. https://github.com/libp2p/rust-libp2p/tree/master/transports/noise
7. https://github.com/libp2p/go-libp2p/tree/master/p2p/security/noise
