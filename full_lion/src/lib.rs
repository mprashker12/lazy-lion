use square_reed_solomon::prover;
pub mod node;

pub trait AbstractChannel {}

pub trait ChannelSender<C: AbstractChannel> {}
