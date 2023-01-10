#[cfg(test)]
mod identify {
    use libp2p::{
        futures::StreamExt, identify, identity, swarm::SwarmEvent, Multiaddr, PeerId, Swarm,
    };

    #[tokio::test]
    async fn test_identify() {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        println!("Local peer id: {:?}", local_peer_id);

        let transport = libp2p::tokio_development_transport(local_key.clone()).unwrap();

        let behaviour = identify::Behaviour::new(identify::Config::new(
            "/ipfs/id/1.0.0".to_string(),
            local_key.public(),
        ));

        let mut swarm = Swarm::with_tokio_executor(transport, behaviour, local_peer_id);

        // Tell the swarm to listen on all interfaces and a random, OS-assigned
        // port.
        swarm
            .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .unwrap();

        // Dial the peer identified by the multi-address given as the second
        // command-line argument, if any.
        let remote: Multiaddr = String::from("/ip4/5.161.92.43/tcp/4001").parse().unwrap();
        swarm.dial(remote).unwrap();

        loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
                // Prints peer id identify info is being sent to.
                SwarmEvent::Behaviour(identify::Event::Sent { peer_id, .. }) => {
                    println!("Sent identify info to {peer_id:?}")
                }
                // Prints out the info received via the identify event
                SwarmEvent::Behaviour(identify::Event::Received { info, .. }) => {
                    println!("Received {info:?}")
                }
                _ => {}
            }
        }
    }
}

/*

Received Info {
    public_key: Ed25519(PublicKey(compressed): 50c7eee464eb7265ee953341fe26cbbbe8464fff457e53ac696351f9ff4d75bf),
    protocol_version: "ipfs/0.1.0",
    agent_version: "go-ipfs/0.12.2/0e8b121ab-dirty",
    listen_addrs: ["/ip4/5.161.92.43/tcp/4001", "/ip6/2a01:4ff:f0:3b1e::1/tcp/4001",
        "/ip4/5.161.92.43/udp/4001/quic", "/ip6/2a01:4ff:f0:3b1e::1/udp/4001/quic",
        "/ip6/64:ff9b::5a1:5c2b/udp/4001/quic"],
    protocols: ["/p2p/id/delta/1.0.0", "/ipfs/id/1.0.0",
    "/ipfs/id/push/1.0.0", "/ipfs/ping/1.0.0", "/libp2p/circuit/relay/0.1.0",
    "/libp2p/circuit/relay/0.2.0/stop", "/ipfs/lan/kad/1.0.0", "/libp2p/autonat/1.0.0",
    "/ipfs/bitswap/1.2.0", "/ipfs/bitswap/1.1.0", "/ipfs/bitswap/1.0.0", "/ipfs/bitswap", "/x/",
    "/ipfs/kad/1.0.0", "/libp2p/circuit/relay/0.2.0/hop"],
    observed_addr: "/ip4/51.190.231.74/tcp/50914" }
*/
