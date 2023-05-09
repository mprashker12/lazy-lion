mod rs_line;

pub mod rs_square;
pub mod prover;

#[cfg(test)]
mod tests {
    use crate::prover::RsSquareProver;
    use crate::verifier::RsSquareVerifier;
    use crate::rs_line::RsLine;

    // Use BLS12_381 (pairing-friendly EC) for KZG
    use ark_test_curves::bls12_381::Bls12_381;
    use ark_test_curves::bls12_381::Fr;
    use crate::rs_square::RsSquare;

    #[test]
    pub fn basic_rs_prover() {
        // arrange data shares into n by n grid (n must be power of 2)
        let shares = vec![
            vec![Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)],
            vec![Fr::from(4), Fr::from(5), Fr::from(6), Fr::from(7)],
            vec![Fr::from(8), Fr::from(9), Fr::from(10), Fr::from(11)],
            vec![Fr::from(12), Fr::from(13), Fr::from(14), Fr::from(15)],
        ];

        // scale factor to dilate original shares (must be a power of 2)
        let scale: usize = 2;

        let mut prover = RsSquareProver::<Bls12_381>::new(&shares, scale);
    }
}
