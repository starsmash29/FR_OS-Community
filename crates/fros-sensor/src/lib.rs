//! What FR_OS 2's sensor crates (fros-tlsfp, fros-appid, fros-aiids, fros-iot)
//! share to answer exactly as FR_OS 1.x's Python does: the differential
//! tests compare their output with 1.x's byte for byte, so Python's
//! rules are spelled out here once rather than approximated in each.
//!
//! - [`pyjson`]: `json.loads`/`json.dumps` and the conversions 1.x
//!   applies to what it read;
//! - [`ordered`]: dicts in insertion order, and `min`/`max` as Python
//!   picks among equals and NaNs;
//! - [`pytext`]: `str.isspace`, `str.strip`, `re`'s `\d`, `repr` and
//!   `str` of any JSON value;
//! - [`pyfloat`]: `statistics.mean`/`pstdev`, `round(x, n)`, `sum` and
//!   float `//`, which Python computes exactly or compensated;
//! - [`dnsmasq`]: the timestamp prefix of dnsmasq's query log;
//! - [`helper`]: asking the apply-helper, as 1.x's client does;
//! - [`reference`]: reading the recorded 1.x cases in the tests.

pub mod dnsmasq;
pub mod helper;
pub mod ordered;
pub mod pyfloat;
pub mod pyjson;
pub mod pytext;
pub mod reference;
mod unicode_tables;
