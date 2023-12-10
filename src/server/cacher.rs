use std::collections::HashMap;

use futures::Future;
use tracing::trace;

pub struct Cacher<Ident, Data> {
    pub map: HashMap<Ident, Data>,
}

impl<Ident, Data> Cacher<Ident, Data>
where
    Ident: std::cmp::Eq + std::hash::Hash + Clone + std::fmt::Debug,
    Data: Clone + std::fmt::Debug,
{
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
    pub async fn fetch<F, Fut, Identifier>(
        &mut self,
        keys: Vec<Ident>,
        get_components: F,
        determine_identifier: Identifier,
    ) -> anyhow::Result<Vec<Data>>
    where
        F: Fn(Vec<Ident>) -> Fut,
        Fut: Future<Output = anyhow::Result<Vec<Data>>>,
        Identifier: Fn(&Data) -> Ident,
    {
        // Get items that are not yet cached
        let keys_to_request: Vec<Ident> = keys
            .clone()
            .into_iter()
            .filter(|key| !self.map.contains_key(key))
            .collect();

        trace!(
            "{} to be fetched out of {}",
            keys_to_request.len(),
            keys.len()
        );
        let new_responses = get_components(keys_to_request).await?;
        trace!("keys received and to be cached: {}", new_responses.len());

        // Insert new responses into cache
        new_responses.into_iter().for_each(|item| {
            self.map.insert(determine_identifier(&item), item.clone());
        });

        trace!("{:?}", self.map);
        // Now just pull out the original requests because they should all be cached
        let mut result = vec![];
        for key in keys {
            trace!("checking key: {:?}", key);
            if let Some(item) = self.map.get(&key) {
                trace!("{:?}", item);
                result.push(item.clone());
            }
        }
        anyhow::Ok(result)
    }
}

#[cfg(test)]
mod test {

    use super::Cacher;

    #[tokio::test]
    async fn test_cache() {
        let mut cacher = Cacher::<String, String>::new();

        let keys = vec!["a".to_string(), "b".to_string(), "c".to_string()];

        let responses = cacher
            .fetch(keys.clone(), get_components, get_identifier)
            .await;

        let expected_responses = vec![
            "a-response".to_string(),
            "b-response".to_string(),
            "c-response".to_string(),
        ];
        assert_eq!(responses.unwrap(), expected_responses);
    }

    async fn get_components(keys: Vec<String>) -> anyhow::Result<Vec<String>> {
        Ok(keys
            .iter()
            .map(|key| format!("{}-response", key))
            .collect::<Vec<_>>())
    }

    fn get_identifier(item: &String) -> String {
        item.split('-').next().unwrap().to_string()
    }
}
