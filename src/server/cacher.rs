#![allow(dead_code)]
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub struct Cacher<Ident, Data> {
    pub map: Arc<Mutex<HashMap<Ident, Data>>>,
}

impl<Ident, Data> Cacher<Ident, Data>
where
    Ident: std::cmp::Eq + std::hash::Hash + Clone + std::fmt::Debug,
    Data: Clone + std::fmt::Debug,
{
    pub fn new() -> Self {
        Self {
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get(&self, keys: &[Ident]) -> Option<HashMap<Ident, Data>> {
        let cache = self.map.lock().unwrap();

        // filter out the keys that are already cached
        let values_cached = keys
            .iter()
            .filter_map(|key| cache.get(key).map(|value| (key.clone(), value.clone())))
            .collect::<HashMap<Ident, Data>>();

        Some(values_cached)
    }

    pub fn find_not_found_keys(&self, keys: &[Ident]) -> Vec<Ident> {
        let cache = self.map.lock().unwrap();

        keys.iter()
            .filter(|k| !cache.contains_key(k))
            .cloned()
            .collect()
    }

    pub fn put(&self, key: Ident, value: Data) {
        let mut cache = self.map.lock().unwrap();
        cache.insert(key, value);
    }
}
