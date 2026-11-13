//! An insertion-ordered map, and `min` with Python's semantics: 1.x
//! keeps its flows and inventory in dicts and evicts with `min(...)`,
//! which picks the *first* of equal keys in insertion order and, with a
//! NaN about, keeps whatever `<` never beat. Matching that exactly is
//! what makes eviction replay the same.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::hash::Hash;

pub(crate) struct OrderedMap<K, V> {
    slots: Vec<Option<(K, V)>>,
    index: HashMap<K, usize>,
}

impl<K: Eq + Hash + Clone, V> OrderedMap<K, V> {
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::new(),
            index: HashMap::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.index.len()
    }

    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        let &i = self.index.get(key)?;
        self.slots.get(i)?.as_ref().map(|(_, v)| v)
    }

    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let &i = self.index.get(key)?;
        self.slots.get_mut(i)?.as_mut().map(|(_, v)| v)
    }

    /// Like a dict assignment: a key already there keeps its place.
    pub(crate) fn insert(&mut self, key: K, value: V) {
        if let Some(&i) = self.index.get(&key)
            && let Some(slot) = self.slots.get_mut(i)
        {
            *slot = Some((key, value));
            return;
        }
        self.index.insert(key.clone(), self.slots.len());
        self.slots.push(Some((key, value)));
    }

    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        let i = self.index.remove(key)?;
        let removed = self.slots.get_mut(i)?.take().map(|(_, v)| v);
        if self.slots.len() > 32 && self.index.len() * 2 < self.slots.len() {
            self.compact();
        }
        removed
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        let mut dropped = Vec::new();
        for (k, v) in self.iter() {
            if !keep(k, v) {
                dropped.push(k.clone());
            }
        }
        for k in &dropped {
            self.remove(k);
        }
    }

    fn compact(&mut self) {
        self.slots.retain(Option::is_some);
        self.index.clear();
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some((k, _)) = slot {
                self.index.insert(k.clone(), i);
            }
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.slots.iter().flatten().map(|(k, v)| (k, v))
    }
}

/// Python's `min(d, key=...)` over a dict's items in insertion order:
/// the first item whose key is `<` every earlier minimum.
pub(crate) fn py_min_by<'a, K: 'a, V: 'a>(
    items: impl Iterator<Item = (&'a K, &'a V)>,
    key: impl Fn(&V) -> f64,
) -> Option<&'a K> {
    let mut best: Option<(&K, f64)> = None;
    for (k, v) in items {
        let value = key(v);
        match best {
            Some((_, current)) if value.partial_cmp(&current) != Some(Ordering::Less) => {}
            _ => best = Some((k, value)),
        }
    }
    best.map(|(k, _)| k)
}

/// Python's `max(values)`: the first value `>` every earlier maximum.
pub(crate) fn py_max(values: impl Iterator<Item = f64>) -> Option<f64> {
    let mut best: Option<f64> = None;
    for value in values {
        match best {
            Some(current) if value.partial_cmp(&current) != Some(Ordering::Greater) => {}
            _ => best = Some(value),
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_survives_removal_and_reinsertion() {
        let mut m = OrderedMap::new();
        for i in 0..100 {
            m.insert(i, i);
        }
        for i in 0..90 {
            m.remove(&i);
        }
        m.insert(95, 0); // keeps its place
        m.insert(5, 5); // goes last
        let keys: Vec<i32> = m.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec![90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 5]);
        assert_eq!(m.get(&95), Some(&0));
    }

    #[test]
    fn min_and_max_follow_python() {
        let m: Vec<(i32, f64)> = vec![(1, 2.0), (2, 1.0), (3, 1.0)];
        let it = m.iter().map(|(k, v)| (k, v));
        assert_eq!(py_min_by(it, |v| *v), Some(&2));
        let n: Vec<(i32, f64)> = vec![(1, f64::NAN), (2, 1.0)];
        assert_eq!(py_min_by(n.iter().map(|(k, v)| (k, v)), |v| *v), Some(&1));
        assert_eq!(py_max([1.0, f64::NAN, 3.0].into_iter()), Some(3.0));
        assert!(py_max([f64::NAN, 3.0].into_iter()).unwrap().is_nan());
    }
}
