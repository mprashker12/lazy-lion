use crate::rs_line::RsLine;
use std::fmt::{Debug, Formatter};

use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};

pub struct RsSquare<F: PrimeField> {
    /// Original shares are presented as n_row by n_row field elements
    n_rows: usize,
    /// Factor used to scale original data square to encoded square
    scale: usize,
    /// Encoded square side-length (= n_rows*scale)
    length: usize,
    /// Rows of the Encoded Square
    rows: Vec<RsLine<F>>,
    /// 2-adic domain used to interpolate original data shares over
    small_domain: Radix2EvaluationDomain<F>,
    /// 2-adic domain used to evaluate interpolated polynomials
    /// over to fill in the encoded square
    large_domain: Radix2EvaluationDomain<F>,
}

impl<F: PrimeField> Debug for RsSquare<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for rid in 0..self.length {
            let _ = writeln!(f, "{:?}", &self.rows[rid]);
        }
        Ok(())
    }
}

impl<F: PrimeField> RsSquare<F> {
    pub fn new(data_rows: &[RsLine<F>], scale: usize) -> Self {
        let n_rows = data_rows.len();
        assert!(is_power_of_two(n_rows), "Number of rows must be power of 2");
        assert!(is_power_of_two(scale), "Scale factor must be power of 2");

        let length = n_rows * scale;

        let large_domain = Radix2EvaluationDomain::<F>::new(length).unwrap_or_else(|| {
            panic!(
                "Domain does not have roots of unity of order {} = {}*{}",
                length, n_rows, scale
            );
        });

        let small_domain = Radix2EvaluationDomain::<F>::new(n_rows).unwrap();

        let zero_vec = vec![F::zero(); n_rows];
        let mut rows = Vec::<_>::with_capacity(length);
        for idx in 0..length {
            if idx % scale == 0 {
                assert_eq!(
                    data_rows[idx / scale].length(),
                    length,
                    "Data rows do not form a square"
                );
                rows.push(data_rows[idx / scale].clone())
            } else {
                rows.push(RsLine::new(&zero_vec, scale));
            }
        }

        Self {
            n_rows,
            scale,
            length,
            rows,
            small_domain,
            large_domain,
        }
    }

    fn set_row(&mut self, rid: usize, line: &RsLine<F>) {
        for cid in 0..self.length {
            self.rows[rid].set_element_at(cid, line.get_element_at(cid));
        }
    }

    fn set_col(&mut self, cid: usize, line: &RsLine<F>) {
        for rid in 0..self.length {
            self.rows[rid].set_element_at(cid, line.get_element_at(rid));
        }
    }

    pub fn val_at(&self, rid: usize, cid: usize) -> F {
        self.rows[rid].get_element_at(cid)
    }

    pub fn extend(&mut self) {
        // extend rows for which we originally have data shares in
        for rid in 0..self.n_rows {
            self.extend_row(rid * self.scale);
        }
        // each column now has enough shares to extend
        for cid in 0..self.length {
            self.extend_col(cid);
        }
        // extend rows we originally did not have enough shares to extend
        for rid in 0..self.length {
            if rid % self.scale == 0 {
                continue;
            }
            self.extend_row(rid);
        }
    }

    fn extend_row(&mut self, rid: usize) {
        self.rows[rid].extend(self.small_domain, self.large_domain);
    }

    pub fn row_poly(&self, rid: usize) -> DensePolynomial<F> {
        Evaluations::from_vec_and_domain(self.rows[rid].compressed_vals(), self.small_domain)
            .interpolate()
    }

    pub fn col_poly(&self, cid: usize) -> DensePolynomial<F> {
        let mut col = vec![];
        for rid in 0..self.n_rows {
            col.push(self.rows[rid * self.scale].get_element_at(cid));
        }

        Evaluations::from_vec_and_domain(col, self.small_domain).interpolate()
    }

    fn extend_col(&mut self, cid: usize) {
        // we don't have immediate access to the column,
        // so first build it, then extend it, then set it in the square.
        let mut col = vec![];
        for rid in 0..self.n_rows {
            col.push(self.rows[rid * self.scale].get_element_at(cid));
        }
        let mut rs_line = RsLine::new(&col, self.scale);
        rs_line.extend(self.small_domain, self.large_domain);
        self.set_col(cid, &rs_line);
    }
}

pub fn is_power_of_two(x: usize) -> bool {
    if x == 0 {
        return false;
    }
    if x & (x - 1) == 0 {
        return true;
    }
    false
}

mod tests {
    use rs_line::RsLine;

    // Use BLS12_381 (pairing-friendly EC) for KZG
    use crate::rs_line;
    use crate::rs_square::RsSquare;
    use ark_test_curves::bls12_381::Bls12_381;
    use ark_test_curves::bls12_381::Fr;

    #[test]
    pub fn basic_square() {
        let shares = vec![
            vec![Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)],
            vec![Fr::from(4), Fr::from(5), Fr::from(6), Fr::from(7)],
            vec![Fr::from(8), Fr::from(9), Fr::from(10), Fr::from(11)],
            vec![Fr::from(12), Fr::from(13), Fr::from(14), Fr::from(15)],
        ];

        let scale = 4;
        let lines: Vec<RsLine<_>> = shares
            .clone()
            .into_iter()
            .map(|share| RsLine::new(&share, scale))
            .collect();

        let mut square = RsSquare::new(lines.as_slice(), scale);
        square.extend();

        // square should now be 4*4 x 4*4 and should contain original entries at (x,y) coords
        // with x and y divisible by 4.
        for rid in 0..4 {
            for cid in 0..4 {
                assert_eq!(square.val_at(rid * scale, cid * scale), shares[rid][cid]);
            }
        }
    }
}
