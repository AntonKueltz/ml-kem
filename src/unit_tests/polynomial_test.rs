use crate::polynomial::*;

#[test]
fn test_encode_decode_dv5() {
    for start in (0..Q as usize).step_by(N) {
        let mut p = Polynomial::new(PolynomialRepresentation::STANDARD);
        for i in 0..N {
            p.f[i] = ((start + i) % Q as usize) as i16;
        }

        let c = p.compress_encode(5);
        let q = Polynomial::decode_decompress(&c, 5);

        for i in 0..N {
            let (x, y) = (q.f[i], p.f[i]);
            let e = (y - x).rem_euclid(Q);
            assert!(e.min(Q - e) <= 52, "i={i} x={x} y={y}");
        }

        let c_ = q.compress_encode(5);
        assert_eq!(c_, c);
    }
}

#[test]
fn test_encode_decode_dv4() {
    for start in (0..Q as usize).step_by(N) {
        let mut p = Polynomial::new(PolynomialRepresentation::STANDARD);
        for i in 0..N {
            p.f[i] = ((start + i) % Q as usize) as i16;
        }

        let c = p.compress_encode(4);
        let q = Polynomial::decode_decompress(&c, 4);

        for i in 0..N {
            let (x, y) = (q.f[i], p.f[i]);
            let e = (y - x).rem_euclid(Q);
            assert!(e.min(Q - e) <= 104, "i={i} x={x} y={y}");
        }

        let c_ = q.compress_encode(4);
        assert_eq!(c_, c);
    }
}
