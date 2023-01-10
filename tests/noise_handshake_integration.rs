
#[cfg(test)]
mod kad {
    use ed25519_dalek::Keypair;
    use ipfs_handshake::{connection::{multistream::Multistream, Connection}, auth::noise::protocol::NoiseProtocol};
    use rand::rngs::OsRng;

    /*
     Working nodes: 
        - 147.75.84.175:4001 (Web3 Storage) https://github.com/web3-storage/web3.storage/blob/main/PEERS
        - 139.178.88.145:4001 (Web3 Storage)
        - 5.161.92.43:4001 (StorJ) https://docs.ipfs.tech/how-to/peering-with-content-providers/#content-provider-list
    
    */

    #[test]
    fn test_handshake() {
        let peer_id: Keypair = Keypair::generate(&mut OsRng);
        let connection = Multistream::connect("5.161.92.43:4001".parse().unwrap()).unwrap();

        // Consumes a connection so that you may only communicate securely
        let mut secure_channel = Multistream::upgrade::<NoiseProtocol>(connection, peer_id).unwrap();


        let response = secure_channel.read().unwrap();
        print!("RESP: {}\n", std::str::from_utf8(&response).unwrap());
        secure_channel.write(b"/multistream/1.0.0\n").unwrap();
        // /mplex/1.0.0
        secure_channel.write(b"/yamux/1.0.0\n").unwrap();
        let response = secure_channel.read().unwrap();

        let protocol_name = "/ipfs/id/1.0.0\n";
        let yam_ver = 0u8;
        let yam_type = 0u8;
        let yam_flag = 1u16.to_be_bytes();
        let yam_stream_id = 1u32.to_be_bytes();
        let yam_length = ((protocol_name.len() as i32) + 1).to_be_bytes();
        let yam_header = [&[yam_ver][..], &[yam_type][..], &yam_flag[..], &yam_stream_id[..], &yam_length[..]].concat();




        print!("RESP: {}\n", std::str::from_utf8(&response).unwrap());
    }
    
}
