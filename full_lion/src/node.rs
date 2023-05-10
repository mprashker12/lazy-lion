use square_reed_solomon::{prover::RsSquareProver, rs_square::RsSquare};

use rs_merkle::{MerkleTree, algorithms::Sha256, Hasher};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use anyhow::Result;

use std::sync::Mutex;
use std::sync::Arc;


use tokio::net::{TcpSocket, TcpStream};

pub struct FullLionNode<E : Pairing, H : Hasher> {
    square: RsSquare<E::ScalarField>,
    inner: FullLionNodeInner<E, H>,
}

#[derive(Clone)]
pub struct FullLionNodeInner<E: Pairing, H: Hasher> {
    prover: Arc<Mutex<RsSquareProver<E, H>>>,
}

impl<E : Pairing, H : Hasher> FullLionNode<E, H> {

    pub fn new(data: &[u8], stream: TcpStream) -> Self {
        todo!();
    }


    pub async fn run(&mut self) -> Result<()> {
        loop {}
    }


}
