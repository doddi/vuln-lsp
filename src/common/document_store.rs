use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Debug)]
pub struct DocumentStore<K, V>
where
    K: std::hash::Hash,
    K: std::cmp::Eq,
    V: Clone,
{
    pub inner: Arc<Mutex<HashMap<K, V>>>,
}

impl<K, V> DocumentStore<K, V>
where
    K: Clone + Eq + std::hash::Hash,
    V: Clone,
{
    pub(crate) fn new() -> Self {
        DocumentStore {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn insert(&self, key: &K, value: V) {
        self.inner.lock().unwrap().insert(key.clone(), value);
    }

    pub(crate) fn get(&self, key: &K) -> Option<V> {
        self.inner.lock().unwrap().get(key).cloned()
    }

    pub(crate) fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }
}
