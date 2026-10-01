use crate::matrix::*;

#[test]
fn test_encode_decode_du11() {
    for start in (0..Q as usize).step_by(N * 4) {
        let mut u = Vector::new(4);
        for i in 0..4 {
            let mut p = Polynomial::new(PolynomialRepresentation::STANDARD);
            for j in 0..N {
                p.f[j] = ((start + N * i + j) % Q as usize) as i16;
            }
            u.push(p);
        }

        let c = u.compress_encode(11);
        let v = Vector::decode_decompress(&c, 4, 11);

        for i in 0..4 {
            for j in 0..N {
                let (x, y) = (u.coords[i].f[j], v.coords[i].f[j]);
                let e = (y - x).rem_euclid(Q);
                assert!(e.min(Q - e) <= 1, "i={i} j={j} x={x} y={y}");
            }
        }

        let c_ = v.compress_encode(11);
        assert_eq!(c_, c);
    }
}

#[test]
fn test_encode_decode_du10() {
    for start in (0..Q as usize).step_by(N * 3) {
        let mut u = Vector::new(3);
        for i in 0..3 {
            let mut p = Polynomial::new(PolynomialRepresentation::STANDARD);
            for j in 0..N {
                p.f[j] = ((start + N * i + j) % Q as usize) as i16;
            }
            u.push(p);
        }

        let c = u.compress_encode(10);
        let v = Vector::decode_decompress(&c, 3, 10);

        for i in 0..3 {
            for j in 0..N {
                let (x, y) = (u.coords[i].f[j], v.coords[i].f[j]);
                let e = (y - x).rem_euclid(Q);
                assert!(e.min(Q - e) <= 2, "i={i} j={j} x={x} y={y}");
            }
        }

        let c_ = v.compress_encode(10);
        assert_eq!(c_, c);
    }
}
