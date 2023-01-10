## References
1. https://discuss.libp2p.io/t/s-kademlia-lookups-over-disjoint-paths-in-rust-libp2p/571
2. https://ipfs.io/ipfs/QmR7GSQM93Cx5eAg6a6yRzNde1FQv7uL6X1o4k7zrJa3LX/ipfs.draft3.pdf
3. https://attachment.victorlampcdn.com/article/content/20220705/SKademlia_2007.pdf
4. https://github.com/f0lg0/kademlia-dht/blob/main/src/protocol.rs 



## Peer ID
In line with the S/Kademlia paper, the PeerId in libp2p is a hash over the public key.
> Nodes are identified by a NodeId, the cryptographic hash3 of a public-key, created with S/Kademlia’s **static crypto puzzle** [1].

## Connecting with peers
Upon first connecting, 
1. Peers exchange public keys
2. Check: hash(other.PublicKey) == other.NodeId. 
3. If not, the connection is terminated.


## Key-gen:
Inspecting the Kubo CLI, RSA or ed25519 are used:
- https://docs.ipfs.tech/reference/kubo/cli/#ipfs-key-export

## Performance
ed25519 was shown to be the best performing schema:
- https://goteleport.com/blog/comparing-ssh-keys/


## Transport Protocol
The IPFS white paper suggests using web-rtc:
- https://ipfs.io/ipfs/QmR7GSQM93Cx5eAg6a6yRzNde1FQv7uL6X1o4k7zrJa3LX/ipfs.draft3.pdf


## Handshaking
- https://docs.rs/libp2p/latest/libp2p/core/upgrade/index.html

Upgrade process
An upgrade is performed in two steps:

A protocol negotiation step. The UpgradeInfo::protocol_info method is called to determine which protocols are supported by the trait implementation. The multistream-select protocol is used in order to agree on which protocol to use amongst the ones supported.

A handshake. After a successful negotiation, the InboundUpgrade::upgrade_inbound or OutboundUpgrade::upgrade_outbound method is called. This method will return a Future that performs a handshake. This handshake is considered mandatory, however in practice it is possible for the trait implementation to return a dummy Future that doesn’t perform any action and immediately succeeds.

After an upgrade is successful, an object of type InboundUpgrade::Output or OutboundUpgrade::Output is returned. The actual object depends on the implementation and there is no constraint on the traits that it should implement, however it is expected that it can be used by the user to control the behaviour of the protocol.

Note: You can use the apply_inbound or apply_outbound methods to try upgrade a connection or substream. However if you use the recommended Swarm or ConnectionHandler APIs, the upgrade is automatically handled for you and you don’t need to use these methods.