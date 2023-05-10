use crate::rs_line::RsLine;
use crate::rs_square::RsSquare;

use rand::rngs::OsRng;
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::{self, Powers, VerifierKey, KZG10};
use ark_serialize::CanonicalSerialize;
use kzg10::Commitment;

pub struct RsSquareProver<E: Pairing, H: Hasher> {
    /// Original square of shares of data
    shares: Vec<Vec<E::ScalarField>>,
    /// Scale used to extend shares to create square
    scale: usize,
    /// Reed-Solomon Encoded square of data
    square: RsSquare<E::ScalarField>,
    max_degree: usize,
    params: kzg10::UniversalParams<E>,
    _pairing_phantom: PhantomData<E>,
    _hasher_phantom: PhantomData<H>,
}

impl<E: Pairing, H: Hasher> RsSquareProver<E, H> {
    pub fn new(shares: &Vec<Vec<E::ScalarField>>, scale: usize) -> Self {
        let lines = shares
            .iter()
            .map(|share| RsLine::new(share, scale))
            .collect::<Vec<_>>();
        let mut square = RsSquare::new(&lines, scale);

        // prover encodes shares to respond to queries
        square.extend();

        let max_degree = shares.len() * scale;

        let params: kzg10::UniversalParams<E> = KZG10::<E, DensePolynomial<E::ScalarField>>::setup(
            max_degree, /* Max degree = side length of square */
            false,
            &mut OsRng::default(),
        )
        .expect("KZG setup failed");

        Self {
            shares: shares.to_owned(),
            scale,
            square,
            params,
            max_degree,
            _pairing_phantom: PhantomData,
            _hasher_phantom: PhantomData,
        }
    }

    pub fn commit_to_row(&self, rid: usize) -> Commitment<E> {
        self.commit_to_poly(&self.square.row_poly(rid))
    }

    pub fn commit_to_col(&self, cid: usize) -> Commitment<E> {
        self.commit_to_poly(&self.square.col_poly(cid))
    }

    fn commit_to_poly(&self, poly: &DensePolynomial<E::ScalarField>) -> Commitment<E> {
        let powers = Powers {
            powers_of_g: std::borrow::Cow::Owned(
                self.params.powers_of_g[..=self.max_degree].to_owned(),
            ),
            powers_of_gamma_g: std::borrow::Cow::Owned(
                (0..=self.max_degree)
                    .map(|i| self.params.powers_of_gamma_g[&i])
                    .collect(),
            ),
        };

        // not a hiding commitment, so hiding_bound = None and no Randomness Engine.
        let (com, _) =
            KZG10::<E, DensePolynomial<E::ScalarField>>::commit(&powers, poly, None, None)
                .expect("KZG commitment failed");
        com
    }

    fn hash_commitment(&self, com: Commitment<E>) -> H::Hash {
        let com_point = com.0;
        let mut bytes: Vec<u8> = vec![];
        let _ = com_point
            .serialize_uncompressed(&mut bytes)
            .expect("Serializing commitment point should not fail");
        H::hash(bytes.as_slice())
    }

    pub fn row_root(&self) -> H::Hash {
        let leaves: Vec<H::Hash> = (0..self.max_degree)
            .map(|rid| self.hash_commitment(self.commit_to_row(rid)))
            .collect();
        let row_tree = MerkleTree::<H>::from_leaves(leaves.as_slice());
        row_tree
            .root()
            .expect("Merkle root construction of rows should succeed")
    }

    pub fn col_root(&self) -> H::Hash {
        let leaves: Vec<H::Hash> = (0..self.max_degree)
            .map(|cid| self.hash_commitment(self.commit_to_col(cid)))
            .collect();
        let col_tree = MerkleTree::<H>::from_leaves(leaves.as_slice());
        col_tree
            .root()
            .expect("Merkle root construction of rows should succeed")
    }

    pub fn root(&self) -> H::Hash {
        let row_col_tree = MerkleTree::<H>::from_leaves(&[self.row_root(), self.col_root()]);
        row_col_tree
            .root()
            .expect("Merkle root construction from row and col roots should succeed")
    }
}

#[cfg(test)]
mod tests {
    use crate::prover::RsSquareProver;
    use crate::rs_line::RsLine;

    // Use BLS12_381 (pairing-friendly EC) for KZG
    use crate::rs_square::RsSquare;
    use ark_test_curves::bls12_381::Bls12_381;
    use ark_test_curves::bls12_381::Fr;

    // Use Sha256 for Merkle Hashing
    use rs_merkle::algorithms::Sha256;

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

        let mut prover = RsSquareProver::<Bls12_381, Sha256>::new(&shares, scale);
    }
}
