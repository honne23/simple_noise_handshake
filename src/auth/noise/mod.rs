use ed25519_dalek::SecretKey;
use x25519_dalek::{EphemeralSecret, StaticSecret};

mod cipher;
mod symmetric_state;
pub mod handshake_state;
pub mod protocol;

// number of bytes resultant from a SHA256 hash
pub const DHLEN: usize = 32;
pub const HASHLEN: usize = 32;

pub enum MessagePattern {
    E,
    S,
    Ee,
    Es,
    Se,
    Ss,
}

pub enum PrivateKeyType<'a> {
    EK(&'a EphemeralSecret),
    SK(&'a StaticSecret),
    ED(&'a SecretKey),
}

mod tests {
    
    #[test]
    fn test_xx() {
        use crate::auth::noise::{
            handshake_state::{HandshakeState, StaticKeypair},
            MessagePattern,
        };

        let static_local = StaticKeypair::new();
        let static_remote = StaticKeypair::new();

        let mut hss_local = HandshakeState::new(true, &[], static_local, None, None, None);
        let mut hss_remote = HandshakeState::new(false, &[], static_remote, None, None, None);

        // Write from local
        println!("Local Write -> [e] -> Remote");
        let stage1 = hss_local.write_message(&[], vec![MessagePattern::E]).unwrap();

        // Read and write from remote
        println!("Remote Read: [e]");
        hss_remote.read_message(&stage1, vec![MessagePattern::E]).unwrap();
        println!("Remote Write -> [e, ee, s, es] -> Local");
        let respond = hss_remote.write_message(
            b"2nd stage",
            vec![
                MessagePattern::E,
                MessagePattern::Ee,
                MessagePattern::S,
                MessagePattern::Es,
            ],
        ).unwrap();
        // Read from local
        println!("Local Read: [e, ee, s, es]");
        hss_local.read_message(
            &respond,
            vec![
                MessagePattern::E,
                MessagePattern::Ee,
                MessagePattern::S,
                MessagePattern::Es,
            ],
        ).unwrap();
        // Write back to remote
        println!("Local Write -> [s, se] -> Remote");
        let stage3 =
            hss_local.write_message(b"3rd stage", vec![MessagePattern::S, MessagePattern::Se]).unwrap();
        println!("Remote Read: [s, se]");
        let final_resp =
            hss_remote.read_message(&stage3, vec![MessagePattern::S, MessagePattern::Se]).unwrap();

        println!("output: {}", std::str::from_utf8(&final_resp).unwrap());
    }
}
