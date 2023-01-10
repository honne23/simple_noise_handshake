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

## Testing
Simply run:
```bash
cargo test
```
to execute all tests including intergration tests.

To see debug output run:
```bash
cargo test -- -nocapture
```



## Peer ID
In line with the S/Kademlia paper, the PeerId is an ed25519 public key.



## Key-gen:
Inspecting the Kubo CLI, RSA or ed25519 are used:
- https://docs.ipfs.tech/reference/kubo/cli/#ipfs-key-export