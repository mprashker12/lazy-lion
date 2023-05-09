use crate::rs_line::RsLine;
use crate::rs_square::RsSquare;

use rand::rngs::OsRng;
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::{self, Powers, KZG10, VerifierKey};
use kzg10::Commitment;

pub struct RsSquareProver<E: Pairing> {
    shares: Vec<Vec<E::ScalarField>>,
    scale: usize,
    square: RsSquare<E::ScalarField>,
    max_degree: usize,
    params: kzg10::UniversalParams<E>,
    vk: kzg10::VerifierKey<E>,
    _phantom: PhantomData<E>,
}

impl<E: Pairing> RsSquareProver<E> {
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

        //todo: Move this to an "interaction module"
        let vk = VerifierKey {
            g: params.powers_of_g[0],
            gamma_g: params.powers_of_gamma_g[&0],
            h: params.h,
            beta_h: params.beta_h,
            prepared_h: params.prepared_h.clone(),
            prepared_beta_h: params.prepared_beta_h.clone(),
        };

        Self {
            shares: shares.to_owned(),
            scale,
            square,
            params,
            max_degree,
            vk,
            _phantom: PhantomData,
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

    pub fn prove(&self) {
    }
}
