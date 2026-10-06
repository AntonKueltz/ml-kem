use crate::polynomial::N;
use crate::vector::*;

#[test]
fn test_encode_decode_du11() {
    const K: usize = 4;

    for start in (0..Q as usize).step_by(N * K) {
        let mut u = Vector::<K>::new(PolynomialRepresentation::STANDARD);
        for i in 0..K {
            for j in 0..N {
                u[i][j] = ((start + N * i + j) % Q as usize) as i16;
            }
        }

        let mut c = [0u8; 1408];
        u.compress_encode_11(c.as_mut_slice());
        let v = Vector::<K>::decode_decompress_11(&c.as_mut_slice());

        for i in 0..K {
            for j in 0..N {
                let (x, y) = (u[i][j], v[i][j]);
                let e = (y - x).rem_euclid(Q);
                assert!(e.min(Q - e) <= 1, "i={i} j={j} x={x} y={y}");
            }
        }

        let mut c_ = [0u8; 1408];
        v.compress_encode_11(c_.as_mut_slice());
        assert_eq!(c_, c);
    }
}

#[test]
fn test_encode_decode_du10() {
    const K: usize = 3;

    for start in (0..Q as usize).step_by(N * K) {
        let mut u = Vector::<K>::new(PolynomialRepresentation::STANDARD);
        for i in 0..K {
            for j in 0..N {
                u[i][j] = ((start + N * i + j) % Q as usize) as i16;
            }
        }

        let mut c = [0u8; 960];
        u.compress_encode_10(c.as_mut_slice());
        let v = Vector::<K>::decode_decompress_10(&c.as_mut_slice());

        for i in 0..K {
            for j in 0..N {
                let (x, y) = (u[i][j], v[i][j]);
                let e = (y - x).rem_euclid(Q);
                assert!(e.min(Q - e) <= 2, "i={i} j={j} x={x} y={y}");
            }
        }

        let mut c_ = [0u8; 960];
        v.compress_encode_10(c_.as_mut_slice());
        assert_eq!(c_, c);
    }
}
