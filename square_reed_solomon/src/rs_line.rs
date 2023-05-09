use crate::rs_square::is_power_of_two;

use ark_ff::PrimeField;
use ark_poly::evaluations::univariate::Evaluations;
use ark_poly::{Polynomial, Radix2EvaluationDomain};

#[derive(Clone, Debug)]
pub struct RsLine<F: PrimeField> {
    /// Field elements making up the line
    vals: Vec<F>,
    /// Factor used to scale from original data shares to current line
    scale: usize,
}

impl<F: PrimeField> RsLine<F> {
    pub fn new(shares: &[F], scale: usize) -> Self {
        assert!(
            is_power_of_two(shares.len()),
            "Number of Shares in Reed Solomon Line must be power of 2"
        );
        assert!(
            is_power_of_two(scale),
            "Scale factor of Reed Solomon Line must be power of 2"
        );

        let n_shares = shares.len();
        let mut vals = vec![F::zero(); n_shares * scale];
        for idx in 0..n_shares {
            vals[scale * idx] = shares[idx];
        }

        Self { vals, scale }
    }

    pub fn length(&self) -> usize {
        self.vals.len()
    }

    pub fn get_element_at(&self, idx: usize) -> F {
        self.vals[idx]
    }

    pub fn set_element_at(&mut self, idx: usize, val: F) {
        self.vals[idx] = val;
    }

    pub fn compressed_vals(&self) -> Vec<F> {
        let mut compressed_vals = vec![];
        for idx in 0..self.vals.len() / self.scale {
            compressed_vals.push(self.vals[idx * self.scale]);
        }
        compressed_vals
    }

    pub fn extend(
        &mut self,
        small_domain: Radix2EvaluationDomain<F>,
        large_domain: Radix2EvaluationDomain<F>,
    ) {
        let large_order = (1 << large_domain.log_size_of_group) as usize;
        let poly =
            Evaluations::from_vec_and_domain(self.compressed_vals(), small_domain).interpolate();
        let large_omega = large_domain.group_gen;
        let mut pow = F::one();

        self.vals.clear();
        for _ in 0..large_order {
            self.vals.push(poly.evaluate(&pow));
            pow *= large_omega;
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_test_curves::bls12_381::Fr;

    use super::RsLine;

    #[test]
    pub fn basic_reed_solomon_line_extend() {
        let shares = vec![Fr::from(1), Fr::from(2)];
        let small_domain = Radix2EvaluationDomain::<Fr>::new(2).unwrap();
        let large_domain = Radix2EvaluationDomain::<Fr>::new(4).unwrap();
        let mut rs_line = RsLine::new(&shares, 2);
        rs_line.extend(small_domain, large_domain);
        assert_eq!(shares.to_owned(), rs_line.compressed_vals());
    }
}
