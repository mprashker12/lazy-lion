use square_reed_solomon::{prover::RsSquareProver, rs_square::RsSquare};

use ark_ff::PrimeField;

pub struct FullLionNode<F: PrimeField> {
    square: RsSquare<F>,
    prover: RsSquareProver<F>,
}

impl<F: PrimeField> FullLionNode<F> {}
