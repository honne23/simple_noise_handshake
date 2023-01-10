#[cfg(test)]
mod kad {
    use std::{env, net::SocketAddr};

    use ed25519_dalek::Keypair;
    use noise_handshake::{
        auth::noise::protocol::NoiseProtocol,
        connection::{multistream::Multistream, Connection},
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_handshake() {
        let addr: SocketAddr = env::var("PEER_ADDR")
            .unwrap_or_else(|_| String::from("5.161.92.43:4001"))
            .parse()
            .unwrap();

        let peer_id: Keypair = Keypair::generate(&mut OsRng);
        let connection = Multistream::connect(addr);

        assert!(connection.is_ok(), "peer is not reachable");
        let connection = connection.unwrap();

        // Consumes a connection so that you may only communicate securely
        let secure_channel =
            Multistream::upgrade::<NoiseProtocol>(connection, peer_id);

        assert!(secure_channel.is_ok(), "peer does not support the noise transport");
        let mut secure_channel = secure_channel.unwrap();

        // Negotiate multistream again over a secure connection
        let response = secure_channel.read().unwrap();
        let response = Multistream::deserialize(&response).unwrap();
        assert!(std::str::from_utf8(&response).unwrap() == "/multistream/1.0.0", "peer does not support multistream protocol");

        secure_channel.write(&Multistream::serialize(b"/multistream/1.0.0\n")).unwrap();

        // Negotiate yamux multiplexer
        secure_channel.write(&Multistream::serialize(b"/yamux/1.0.0\n")).unwrap();
        let response = secure_channel.read().unwrap();
        let response = Multistream::deserialize(&response).unwrap();
        assert!(std::str::from_utf8(&response).unwrap() == "/yamux/1.0.0", "peer does not support yamux multiplexing");

        // Setup Yamux connection
        // SYN
        secure_channel.write(&encapsulate_yamux(b"", true)).unwrap();
        let response = secure_channel.read().unwrap();
        assert!(response == vec![0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], "yamux stream not synchronised");
        
        // ACK
        secure_channel.write(&encapsulate_yamux(b"", false)).unwrap();
        let response = secure_channel.read().unwrap();
        assert!(response == vec![0, 1, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0], "yamux stream not acknowledged");

        // Get allowable protocols
        secure_channel.write(&encapsulate_yamux(b"", false)).unwrap();
        let response = secure_channel.read().unwrap();
        let response = decapsulate_yamux(&response);
        print!("YAMUX RESP: {:?}\n", std::str::from_utf8(&response).unwrap());
        
    }

    fn encapsulate_yamux(data: &[u8], init: bool,) -> Vec<u8> {
        let yam_ver = 0u8;
        let yam_type = 0u8;
        let yam_flag = if init {1u16.to_be_bytes() } else { 2u16.to_be_bytes() };
        let yam_stream_id = 3u32.to_be_bytes();
        let yam_length = (data.len() as i32).to_be_bytes();
        [
            &[yam_ver][..],
            &[yam_type][..],
            &yam_flag[..],
            &yam_stream_id[..],
            &yam_length[..],
            &data[..]
        ].concat()
    }

    fn decapsulate_yamux(data: &[u8]) -> Vec<u8> {
        data[12..].to_vec()

    }
}
