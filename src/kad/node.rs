use libp2p::identity::Keypair;
use libp2p::PeerId;
use sha2::{Digest, Sha256};
use uint::construct_uint;

use crate::utils::{xor_distance, Metric};

pub type IpfsId = Vec<u8>;

construct_uint! {
    /// 256-bit unsigned integer.
    pub(super) struct U256(4);
}

#[derive(Clone)]
pub struct Node {
    pub Ipfs_id: IpfsId,
    Multihash: PeerId,
    Keypair: Keypair,
    IP_Address: i64,
    UDP_port: i64,
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let distance = self.distance_to(other);
        distance.cmp(&0)
    }
}

impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.Ipfs_id == other.Ipfs_id
    }
}

impl Eq for Node {}

impl Node {
    fn new() -> Node {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&keypair.public());
        let ipfs_id = Node::gen_ipfs_id(peer_id, 10);
        Node {
            Ipfs_id: ipfs_id,
            Multihash: peer_id,
            Keypair: keypair,
            IP_Address: 0,
            UDP_port: 0,
        }
    }

    fn gen_ipfs_id(peer_id: PeerId, difficulty: u32) -> Vec<u8> {
        loop {
            let mut hasher = Sha256::new();
            hasher.update(&peer_id.to_bytes());
            let puzzle = U256::from_big_endian(&hasher.finalize()[..]);
            let leading_zeros = puzzle.leading_zeros();
            if leading_zeros >= difficulty {
                let mut result: [u8; 256] = [0; 256];
                puzzle.to_big_endian(&mut result);
                break result.to_vec(); // Networking protocols prefer big endian [SOURCE!]
            }
        }
    }
}

impl Metric for Node {
    fn distance_to(&self, other: &Self) -> u64 {
        xor_distance(&self.Ipfs_id, &other.Ipfs_id).unwrap()
    }
}

impl Metric for IpfsId {
    fn distance_to(&self, other: &Self) -> u64 {
        xor_distance(self, other).unwrap()
    }
}
