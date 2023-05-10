use ark_ec::pairing::Pairing;
use square_reed_solomon::{prover::RsSquareProver, rs_square::RsSquare};

use rs_merkle::{MerkleTree, algorithms::Sha256, Hasher};
use ark_ff::PrimeField;
use anyhow::Result;

pub struct FullLionNode<E : Pairing, H : Hasher> {
    square: RsSquare<E::ScalarField>,
    prover: RsSquareProver<E, H>,
}

impl<E : Pairing, H : Hasher> FullLionNode<E, H> {


    pub async fn run(&mut self) -> Result<()> {
        loop {}
    }


}
