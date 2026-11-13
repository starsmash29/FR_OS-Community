//! Float arithmetic as Python does it where Python is not plain IEEE:
//! `statistics.mean` and `statistics.pstdev` (exact sums of fractions,
//! then one correct rounding), `round(x, n)` (to the nearest decimal,
//! ties to even, from the float's exact value), `sum` of floats
//! (Neumaier-compensated since Python 3.12), float `//`, and comparing
//! an int with a float exactly. 1.x's AI-IDS scores with the first
//! three and its app usage buckets with the last two; a naive port
//! drifts in the last bit, and the differential tests compare reprs.

use std::cmp::Ordering;

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};

/// A finite float as `mantissa * 2^exponent`, exactly.
fn decompose(f: f64) -> (BigInt, i64) {
    let bits = f.to_bits();
    let negative = bits >> 63 == 1;
    let biased = ((bits >> 52) & 0x7ff) as i64;
    let fraction = bits & ((1u64 << 52) - 1);
    let (mantissa, exponent) = if biased == 0 {
        (fraction, -1074)
    } else {
        (fraction | (1u64 << 52), biased - 1075)
    };
    let m = BigInt::from(mantissa);
    (if negative { -m } else { m }, exponent)
}

/// `f * 2^k`, exactly when the result is representable.
fn ldexp(mut f: f64, mut k: i64) -> f64 {
    let step = 2f64.powi(1000);
    let back = 2f64.powi(-1000);
    while k > 1000 {
        f *= step;
        k -= 1000;
    }
    while k < -1000 {
        f *= back;
        k += 1000;
    }
    f * 2f64.powi(k as i32)
}

/// `n / d`, correctly rounded (ties to even), as Python's int / int.
/// `sticky` says the true value is a little more than `n / d` (by less
/// than one unit of the last place of `n`): a remainder thrown away
/// before. Overflow gives an infinity (Python raises).
fn ratio(n: &BigInt, d: &BigUint, sticky: bool) -> f64 {
    let negative = n.sign() == Sign::Minus;
    let a = n.magnitude();
    if a.is_zero() && !sticky {
        return 0.0;
    }
    let e = a.bits() as i64 - d.bits() as i64;
    // a * 2^s / d lands in [2^53, 2^55).
    let s = 54 - e;
    let (num, den) = if s >= 0 {
        (a << (s as u64), d.clone())
    } else {
        (a.clone(), d << ((-s) as u64))
    };
    let (q, r) = num.div_rem(&den);
    let sticky = sticky || !r.is_zero();
    // value = (q + sticky) * 2^-s; keep 53 bits, fewer below 2^-1022.
    let bits = q.bits() as i64;
    let mut drop = bits - 53;
    if -s + drop < -1074 {
        drop = -1074 + s;
    }
    let (kept, scale) = if drop > 0 {
        let drop_u = drop as u64;
        let kept = &q >> drop_u;
        let low = &q - (&kept << drop_u);
        let half = BigUint::one() << (drop_u - 1);
        let up = match low.cmp(&half) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => sticky || kept.is_odd(),
        };
        (if up { kept + 1u32 } else { kept }, -s + drop)
    } else {
        (q, -s)
    };
    let mantissa = kept.to_f64().unwrap_or(f64::INFINITY);
    let value = ldexp(mantissa, scale);
    if negative { -value } else { value }
}

fn exact_sums(values: &[f64]) -> (BigInt, BigInt, i64) {
    let parts: Vec<(BigInt, i64)> = values.iter().map(|&v| decompose(v)).collect();
    let low = parts.iter().map(|(_, e)| *e).min().unwrap_or(0);
    let mut sx = BigInt::zero();
    let mut sxx = BigInt::zero();
    for (m, e) in parts {
        let shift = (e - low) as u64;
        sxx += (&m * &m) << (2 * shift);
        sx += m << shift;
    }
    (sx, sxx, low)
}

fn shifted(n: BigInt, d: BigUint, k: i64) -> (BigInt, BigUint) {
    if k >= 0 {
        (n << (k as u64), d)
    } else {
        (n, d << ((-k) as u64))
    }
}

/// `statistics.mean(values)`. Values must be finite (NaN if not, where
/// Python would give an infinity or NaN); NaN for none (Python raises).
pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() || values.iter().any(|v| !v.is_finite()) {
        return f64::NAN;
    }
    let (sx, _, low) = exact_sums(values);
    let (n, d) = shifted(sx, BigUint::from(values.len()), low);
    ratio(&n, &d, false)
}

/// `statistics.pstdev(values)`: the square root of the exact population
/// variance, correctly rounded (Python's `_float_sqrt_of_frac`). Values
/// must be finite; NaN otherwise, or for none (Python raises).
pub fn pstdev(values: &[f64]) -> f64 {
    if values.is_empty() || values.iter().any(|v| !v.is_finite()) {
        return f64::NAN;
    }
    let (sx, sxx, low) = exact_sums(values);
    let count = BigInt::from(values.len());
    // variance = (n*Sxx - Sx^2) / n^2 * 2^(2*low); never negative.
    let v = (&count * sxx - &sx * &sx).magnitude().clone();
    let n2 = count.magnitude() * count.magnitude();
    let (num, den) = if low >= 0 {
        (v << ((2 * low) as u64), n2)
    } else {
        (v, n2 << ((-2 * low) as u64))
    };
    sqrt_of_ratio(&num, &den)
}

/// The square root of `n / m`, correctly rounded: an integer square root
/// with at least 54 bits, rounded to odd, then one rounding to a float.
fn sqrt_of_ratio(n: &BigUint, m: &BigUint) -> f64 {
    if n.is_zero() {
        return 0.0;
    }
    let q = (n.bits() as i64 - m.bits() as i64 - 109).div_euclid(2);
    let rto = |n: &BigUint, m: &BigUint| -> (BigUint, bool) {
        let a = (n / m).sqrt();
        let inexact = &a * &a * m != *n;
        (a, inexact)
    };
    if q >= 0 {
        let (a, inexact) = rto(n, &(m << ((2 * q) as u64)));
        let odd = if inexact { a | BigUint::one() } else { a };
        ratio(&BigInt::from(odd << (q as u64)), &BigUint::one(), false)
    } else {
        let (a, inexact) = rto(&(n << ((-2 * q) as u64)), m);
        let odd = if inexact { a | BigUint::one() } else { a };
        ratio(
            &BigInt::from(odd),
            &(BigUint::one() << ((-q) as u64)),
            false,
        )
    }
}

/// `round(x, digits)` for a float: the nearest multiple of 10^-digits
/// to the exact value of `x`, ties to even, then the float nearest that.
pub fn round(x: f64, digits: u32) -> f64 {
    if !x.is_finite() || x == 0.0 {
        return x;
    }
    let (m, e) = decompose(x);
    let scale = BigUint::from(10u32).pow(digits);
    let (num, den) = shifted(m * BigInt::from(scale.clone()), BigUint::one(), e);
    let negative = num.sign() == Sign::Minus;
    let (q, r) = num.magnitude().div_rem(&den);
    let twice = r << 1u32;
    let up = match twice.cmp(&den) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => q.is_odd(),
    };
    let k = if up { q + 1u32 } else { q };
    if k.is_zero() {
        return if negative { -0.0 } else { 0.0 };
    }
    let k = BigInt::from_biguint(if negative { Sign::Minus } else { Sign::Plus }, k);
    ratio(&k, &scale, false)
}

/// `sum(values)` of floats: CPython 3.12+'s Neumaier-compensated sum.
pub fn sum(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut total = 0.0f64;
    let mut c = 0.0f64;
    for x in values {
        let t = total + x;
        if total.abs() >= x.abs() {
            c += (total - t) + x;
        } else {
            c += (x - t) + total;
        }
        total = t;
    }
    if c != 0.0 && c.is_finite() {
        total += c;
    }
    total
}

/// Python's `vx // wx` for floats (`float_floor_div`).
pub fn floor_div(vx: f64, wx: f64) -> f64 {
    let m = vx % wx;
    let mut div = (vx - m) / wx;
    if m != 0.0 && (wx < 0.0) != (m < 0.0) {
        div -= 1.0;
    }
    if div != 0.0 {
        let mut floordiv = div.floor();
        if div - floordiv > 0.5 {
            floordiv += 1.0;
        }
        floordiv
    } else {
        0f64.copysign(vx / wx)
    }
}

/// `int(f)` of an integral or other finite float, if it fits.
pub fn to_i128(f: f64) -> Option<i128> {
    if !f.is_finite() {
        return None;
    }
    let (m, e) = decompose(f.trunc());
    let v = if e >= 0 {
        m << (e as u64)
    } else {
        m >> ((-e) as u64)
    };
    v.to_i128()
}

/// Python's exact `int < float` comparison (`None` against a NaN).
pub fn cmp_int_float(i: i128, f: f64) -> Option<Ordering> {
    if f.is_nan() {
        return None;
    }
    if f.is_infinite() {
        return Some(if f > 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let (m, e) = decompose(f);
    let i = BigInt::from(i);
    Some(if e >= 0 {
        i.cmp(&(m << (e as u64)))
    } else {
        (i << ((-e) as u64)).cmp(&m)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert_eq!(
            pstdev(&[1.5, 2.5, 2.5, 2.75, 3.25, 4.75]),
            0.986893273527251
        );
        assert_eq!(mean(&[1e50, 1.0, -1e50]), 1.0 / 3.0);
        assert_eq!(round(0.125, 2), 0.12);
        assert_eq!(round(2.675, 2), 2.67);
        assert_eq!(round(0.375, 2), 0.38);
        assert_eq!(floor_div(-1.5, 3600.0), -1.0);
        assert_eq!(cmp_int_float(3, 2.5), Some(Ordering::Greater));
        assert_eq!(
            ratio(&BigInt::from(1), &BigUint::from(3u32), false),
            1.0 / 3.0
        );
        assert_eq!(
            ratio(&BigInt::from(5), &(BigUint::one() << 1076u32), false),
            5e-324
        );
    }
}
