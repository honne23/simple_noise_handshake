use std::ops::ControlFlow;

/// Assume the [`vec`] is a Vector containing 8 bytes and return the u64 representing those bytes
pub fn assume_u64(vec: Vec<u8>) -> Option<u64> {
    let mut buffer: [u8; 8] = [0; 8];
    match vec.iter().enumerate().try_for_each(|(index, byte)| {
        if index <= 7 {
            buffer[index] = *byte;
            return ControlFlow::Continue(());
        } else {
        }
        ControlFlow::Break(())
    }) {
        ControlFlow::Continue(_) => Some(u64::from_be_bytes(buffer)),
        ControlFlow::Break(_) => None,
    }
}

/// Use the XOR metric to calculate a distance between two arrays of bytes
pub fn xor_distance(a: &Vec<u8>, b: &Vec<u8>) -> Option<u64> {
    match a.len() == b.len() {
        true => assume_u64(a.iter().zip(b).map(|(x, y)| x ^ y).collect::<Vec<u8>>()),
        false => None,
    }
}

/// A trait that defines a metric which satisfies the triangle inequality
pub trait Metric {
    fn distance_to(&self, other: &Self) -> u64;
}
