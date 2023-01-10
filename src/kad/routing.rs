use crate::utils::Metric;

use super::node::{IpfsId, Node};
use libp2p::PeerId;
use std::collections::BinaryHeap;

type IpfsDataKey = Vec<u8>;
type IpfsDataValue = Vec<u8>;

trait IPFSRouting {
    fn find_peer(key: IpfsId);

    fn set_value(&mut self, node: Node);

    fn get_value(&self, key: IpfsDataKey) -> Node;

    fn provide_value(key: PeerId);

    fn find_value_peers(key: PeerId, min: u32);
}

struct Kbucket {
    size: usize,
    contents: BinaryHeap<Node>,
}

struct RoutingTable {
    localhost: Node,
    max_bucket_size: usize,
    k_buckets: [Kbucket],
}

enum Indexable<'a> {
    Node(&'a Node),
    Id(&'a IpfsId),
}

impl RoutingTable {
    /// Given the [`localhost`] and the [`target`], measure the number of matching leading bits of their respective IDs to determine the correct [`Kbucket`] to place the target.
    fn get_bucket_index(&self, target: Indexable) -> usize {
        let distance = match target {
            Indexable::Node(node) => self.localhost.distance_to(node),
            Indexable::Id(id) => self.localhost.Ipfs_id.distance_to(id),
        };
        let distance = distance.to_be_bytes();
        for i in 0..160 {
            for j in (0..8).rev() {
                if (distance[i] >> (7 - j)) & 0x1 != 0 {
                    return i * 8 + j;
                }
            }
        }
        0
    }
}

impl IPFSRouting for RoutingTable {
    fn find_peer(key: IpfsId) {}

    fn set_value(&mut self, node: Node) {
        let bucket_index = self.get_bucket_index(Indexable::Node(&node));
        self.k_buckets[bucket_index].contents.push(node);
    }

    /// Retrieve K-nearest items, unless you have fewer that K-items, in that case return all items
    fn get_value(&self, key: IpfsDataKey) -> Node {
        let bucket_index = self.get_bucket_index(Indexable::Id(&key));

        todo!();
    }

    fn provide_value(key: PeerId) {}

    fn find_value_peers(key: PeerId, min: u32) {}
}
