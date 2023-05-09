use ark_ec::pairing::Pairing;
use square_reed_solomon::rs_square;

use ark_poly_commit::kzg10::{self, Powers, KZG10, VerifierKey};
use ark_poly::univariate::DensePolynomial;
use rand::rngs::OsRng;




pub fn setup<E: Pairing>(params : kzg10::UniversalParams<E>) {

    let vk: ark_poly_commit::kzg10::VerifierKey<E>  = VerifierKey {
        g: params.powers_of_g[0],
        gamma_g: params.powers_of_gamma_g[&0],
        h: params.h,
        beta_h: params.beta_h,
        prepared_h: params.prepared_h.clone(),
        prepared_beta_h: params.prepared_beta_h.clone(),
    };
}