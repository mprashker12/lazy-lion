use std::marker::PhantomData;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

pub struct LightLionNode<E:  Pairing> {
    _pairing_phantom : PhantomData<E>,
}