//! "Does this domain look machine-generated?" (1.x's
//! `frfw.adblock.dga`): the registered label (just left of the public
//! suffix) of at least 10 characters, with a character entropy of at
//! least 3.0 bits and fewer than 40% of its letter pairs among frequent
//! English bigrams. Single-label names and punycode labels are never
//! scored. Only the per-name half of a verdict: the engine needs a burst
//! of such NXDOMAINs from one host.

use fros_sensor::pyfloat;
use fros_sensor::pytext;

/// Second-level labels that are part of a public suffix in many ccTLDs.
const SLD_PUBLIC: [&str; 14] = [
    "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "nic", "ltd", "plc",
];

/// Frequent English letter pairs, as 1.x lists them.
const COMMON_BIGRAMS: &str = "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le \
    ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no \
    ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo \
    ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay \
    ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr \
    cl du ga qu ue ff ba ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt \
    ak pu ui rg ib tl ny ki rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu af \
    hu nn eo vo rv nf xp gn sm fl iz ok nl my gl aw ju oa eq sy sl ps jo";

pub const MIN_LENGTH: usize = 10;
pub const MIN_ENTROPY: f64 = 3.0;
pub const MAX_COMMON_BIGRAM_RATIO: f64 = 0.40;

/// The label a registrant chose (`example` for `www.example.co.uk`);
/// `None` for single-label or malformed names.
pub fn registered_label(name: &str) -> Option<String> {
    let lowered = pytext::lower(name);
    let labels: Vec<&str> = lowered.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    let mut labels = &labels[..labels.len() - 1]; // drop the TLD
    if labels.len() >= 2 && labels.last().is_some_and(|l| SLD_PUBLIC.contains(l)) {
        labels = &labels[..labels.len() - 1];
    }
    let label = labels.last()?;
    let valid = label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    valid.then(|| (*label).to_owned())
}

/// Shannon entropy of the characters, in bits, summed as Python's
/// `sum` does (characters in order of first appearance).
pub fn shannon_entropy(text: &str) -> f64 {
    let mut counts: Vec<(char, usize)> = Vec::new();
    let mut n = 0usize;
    for c in text.chars() {
        n += 1;
        match counts.iter_mut().find(|(k, _)| *k == c) {
            Some((_, count)) => *count += 1,
            None => counts.push((c, 1)),
        }
    }
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    -pyfloat::sum(counts.iter().map(|&(_, c)| {
        let p = c as f64 / n;
        p * p.log2()
    }))
}

fn is_alpha(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphabetic()
    } else {
        c.is_alphabetic()
    }
}

/// The share of letter pairs that are frequent English bigrams.
pub fn common_bigram_ratio(text: &str) -> f64 {
    let chars: Vec<char> = text.chars().collect();
    let mut pairs = 0usize;
    let mut common = 0usize;
    for w in chars.windows(2) {
        if is_alpha(w[0]) && is_alpha(w[1]) {
            pairs += 1;
            let pair: String = w.iter().collect();
            // Two adjacent letters in the list are always one whole entry.
            if COMMON_BIGRAMS.contains(pair.as_str()) {
                common += 1;
            }
        }
    }
    if pairs == 0 {
        return 0.0;
    }
    common as f64 / pairs as f64
}

pub fn looks_generated(name: &str) -> bool {
    let Some(label) = registered_label(name) else {
        return false;
    };
    if label.starts_with("xn--") {
        return false;
    }
    let compact = label.replace('-', "");
    compact.chars().count() >= MIN_LENGTH
        && shannon_entropy(&compact) >= MIN_ENTROPY
        && common_bigram_ratio(&compact) < MAX_COMMON_BIGRAM_RATIO
}
