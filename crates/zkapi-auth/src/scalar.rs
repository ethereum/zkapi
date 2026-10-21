//! Scalar arithmetic in `Z/nZ`, where `n` is the Stark curve group order.
//!
//! Curve scalars (private keys, nonces, blinding factors) live modulo the
//! group order `n`, which is smaller than the base-field prime `p`. Using
//! base-field (`Felt`) arithmetic for scalars is unsound once a value crosses
//! `p`; these helpers do the reduction explicitly via big integers.

use num_bigint::BigUint;
use starknet_types_core::felt::Felt;

/// Stark curve group order `n`.
pub const CURVE_ORDER_HEX: &str =
    "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

fn curve_order() -> BigUint {
    BigUint::parse_bytes(CURVE_ORDER_HEX.as_bytes(), 16).expect("CURVE_ORDER_HEX is valid hex")
}

fn to_uint(f: &Felt) -> BigUint {
    f.to_biguint()
}

fn from_uint(v: BigUint) -> Felt {
    let bytes = v.to_bytes_be();
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    Felt::from_bytes_be(&buf)
}

/// Reduce a field element to its canonical scalar representative mod `n`.
pub fn reduce(a: &Felt) -> Felt {
    from_uint(to_uint(a) % curve_order())
}

/// `(a + b) mod n`.
pub fn add(a: &Felt, b: &Felt) -> Felt {
    from_uint((to_uint(a) + to_uint(b)) % curve_order())
}

/// `(a - b) mod n`.
pub fn sub(a: &Felt, b: &Felt) -> Felt {
    let n = curve_order();
    let a = to_uint(a) % &n;
    let b = to_uint(b) % &n;
    from_uint((a + &n - b) % &n)
}

/// `(a * b) mod n`.
pub fn mul(a: &Felt, b: &Felt) -> Felt {
    from_uint((to_uint(a) * to_uint(b)) % curve_order())
}

/// Reduce arbitrary big-endian bytes to a scalar mod `n` (hash-to-scalar).
pub fn from_bytes_reduced(bytes: &[u8]) -> Felt {
    from_uint(BigUint::from_bytes_be(bytes) % curve_order())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n() -> BigUint {
        curve_order()
    }

    /// The order is the Stark curve's: `n·G` is the identity.
    #[test]
    fn curve_order_annihilates_the_generator() {
        use starknet_types_core::curve::{AffinePoint, ProjectivePoint};
        let g = AffinePoint::generator();
        let g = ProjectivePoint::from_affine(g.x(), g.y()).unwrap();
        let multiply = |k: &BigUint| {
            let mut result = ProjectivePoint::identity();
            let mut temp = g.clone();
            for bit in 0..k.bits() {
                if k.bit(bit) {
                    result = &result + &temp;
                }
                temp = &temp + &temp;
            }
            result
        };
        assert!(
            multiply(&n()).to_affine().is_err(),
            "n·G must be the identity"
        );
        assert!(multiply(&(n() - 1u32)).to_affine().is_ok());
    }

    #[test]
    fn add_wraps_at_order() {
        let n_minus_1 = from_uint(n() - 1u32);
        assert_eq!(add(&n_minus_1, &Felt::from(1u64)), Felt::ZERO);
        assert_eq!(add(&n_minus_1, &Felt::from(3u64)), Felt::from(2u64));
    }

    #[test]
    fn sub_borrows() {
        assert_eq!(
            sub(&Felt::from(2u64), &Felt::from(5u64)),
            from_uint(n() - 3u32)
        );
        assert_eq!(sub(&Felt::from(9u64), &Felt::from(4u64)), Felt::from(5u64));
    }

    #[test]
    fn mul_distributes() {
        // (a + b) * c == a*c + b*c  (mod n)
        let a = Felt::from(123456789u64);
        let b = Felt::from(987654321u64);
        let c = Felt::from(1111111u64);
        assert_eq!(mul(&add(&a, &b), &c), add(&mul(&a, &c), &mul(&b, &c)));
    }
}
