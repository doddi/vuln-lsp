use anyhow::anyhow;
use std::collections::HashMap;

use futures::future;
use reqwest::Url;
use tracing::{debug, trace};

use crate::{
    common::{
        document_store::DocumentStore, errors::VulnLspError, purl::Purl, purl_range::PurlRange,
    },
    parsers::{ParseContent, ParserManager},
    server::{VulnerabilityInformation, VulnerabilityServer, VulnerabilityVersionInfo},
};

pub(crate) struct Middleware {
    server: Box<dyn VulnerabilityServer>,
    document_store: DocumentStore<Url, String>,
    parsed_store: DocumentStore<Url, ParseContent>,
    vuln_store: DocumentStore<Purl, VulnerabilityVersionInfo>,
    security_display_store: DocumentStore<Purl, (Purl, VulnerabilityInformation)>,
    parser_manager: ParserManager,
}

impl Middleware {
    pub(crate) fn new(server: Box<dyn VulnerabilityServer>, parser_manager: ParserManager) -> Self {
        Self {
            server,
            document_store: DocumentStore::new(),
            parsed_store: DocumentStore::new(),
            vuln_store: DocumentStore::new(),
            security_display_store: DocumentStore::new(),
            parser_manager,
        }
    }

    fn cache_new_found_values(&self, vulnerabilities: Vec<VulnerabilityVersionInfo>) {
        vulnerabilities.into_iter().for_each(|vulnerability| {
            self.vuln_store
                .insert(&vulnerability.purl.clone(), vulnerability)
        });
    }

    pub(crate) fn get_calculated_security_information_for_direct_dependency(
        &self,
        direct_dependency: &Purl,
    ) -> Option<(Purl, VulnerabilityInformation)> {
        self.security_display_store.get(direct_dependency)
    }

    pub(crate) async fn update_dependencies(&self, uri: &Url) -> anyhow::Result<()> {
        if let Some(document) = self.document_store.get(uri) {
            trace!("Updating dependencies for {}", uri);

            let parsed_content = self.parser_manager.parse(uri, &document)?;
            self.parsed_store.insert(uri, parsed_content);
            if let Some(parsed_content) = self.parsed_store.get(uri) {
                let vals = parsed_content.transitives.clone().into_values();
                let flattened_dependencies: Vec<Purl> = vals.flatten().collect();
                let dependencies = &flattened_dependencies[..];

                let unknown_purls = self.get_missing_purls_from_vuln_store(dependencies);
                trace!(
                    "There are {} purls not currently cached",
                    unknown_purls.len()
                );

                self.fetch_and_cache_vulnerabilities(&unknown_purls).await;
                self.calculate_security_warning(uri);
                return Ok(());
            }
        }
        Ok(())
    }

    fn calculate_security_warning(&self, url: &Url) {
        if let Some(parsed_content) = self.parsed_store.get(url) {
            self.security_display_store.clear();
            parsed_content
                .ranges
                .iter()
                .for_each(|(direct_dependency, _)| {
                    // Get all the vulnerability information associated with the purl and its transitives
                    if let Some(all_transitive_purls) =
                        &parsed_content.transitives.get(direct_dependency)
                    {
                        let vulnerabilities_for_transitives =
                            self.get_items_from_vuln_store(all_transitive_purls);

                        let mut chosen_purl: Option<Purl> = None;
                        let mut chosen_vulnerability: Option<VulnerabilityInformation> = None;
                        for (purl, vulnerabilities) in vulnerabilities_for_transitives {
                            for vulnerability_information in vulnerabilities.vulnerabilities {
                                // TODO: This is ugly, should be relying on ordering of the strut
                                match chosen_vulnerability {
                                    None => {
                                        chosen_purl = Some(purl.clone());
                                        chosen_vulnerability =
                                            Some(vulnerability_information.clone());
                                    }
                                    Some(ref value) => {
                                        match value
                                            .severity
                                            .cmp(&vulnerability_information.severity)
                                        {
                                            std::cmp::Ordering::Less => {}
                                            std::cmp::Ordering::Equal
                                            | std::cmp::Ordering::Greater => {
                                                chosen_purl = Some(purl.clone());
                                                chosen_vulnerability =
                                                    Some(vulnerability_information.clone());
                                            }
                                        };
                                    }
                                }
                            }
                        }

                        if let Some(chosen_purl) = chosen_purl {
                            if let Some(vulnerability) = chosen_vulnerability {
                                self.security_display_store
                                    .insert(direct_dependency, (chosen_purl, vulnerability));
                            }
                        }
                    }
                });
        }
    }

    fn get_missing_purls_from_vuln_store(&self, dependencies: &[Purl]) -> Vec<Purl> {
        dependencies
            .iter()
            .filter(|dependency| self.vuln_store.get(dependency).is_none())
            .cloned()
            .collect::<Vec<Purl>>()
    }

    fn get_items_from_vuln_store(
        &self,
        dependencies: &[Purl],
    ) -> HashMap<Purl, VulnerabilityVersionInfo> {
        dependencies
            .iter()
            .filter(|dependency| self.vuln_store.get(dependency).is_some())
            .map(|purl| {
                let vuln = self.vuln_store.get(purl).unwrap();
                (purl.clone(), vuln)
            })
            .collect()
    }

    async fn batch(&self, purls: &[Purl]) -> anyhow::Result<Vec<VulnerabilityVersionInfo>> {
        const BATCH_SIZE: usize = 100;
        let chunks = purls.chunks(BATCH_SIZE);
        debug!("Request is split into {} chunks", chunks.len());

        // TODO: How can I keep a counter updated?
        let joins = chunks
            .into_iter()
            .map(|chunk| self.server.get_component_information(chunk));

        match future::try_join_all(joins.into_iter()).await {
            Ok(results) => Ok(results
                .into_iter()
                .flatten()
                .collect::<Vec<VulnerabilityVersionInfo>>()),
            Err(_err) => Err(anyhow!(VulnLspError::ServerError(
                "Error requesting batches".to_string()
            ))),
        }
    }

    async fn fetch_and_cache_vulnerabilities(&self, purls: &[Purl]) {
        if purls.is_empty() {
            debug!("All requested purls found in cache");
        } else if let Ok(vulnerabilities) = self.batch(purls).await {
            // Filter out any responses that have empty vulnerability information
            let vulnerabilities = vulnerabilities
                .into_iter()
                .filter(|v| !v.vulnerabilities.is_empty())
                .collect::<Vec<_>>();
            self.cache_new_found_values(vulnerabilities);
        }
    }

    pub(crate) fn get_purl_position_in_document(
        &self,
        url: &Url,
        line_number: usize,
    ) -> Option<Purl> {
        if let Some(parsed_content) = self.parsed_store.get(url) {
            for (purl, range) in parsed_content.ranges.iter() {
                if range.contains_position(line_number) {
                    return Some(purl.clone());
                }
            }
        }
        None
    }

    pub(crate) fn get_security_information_for_document(
        &self,
        uri: &Url,
    ) -> Vec<(PurlRange, VulnerabilityInformation)> {
        if let Some(parsed_content) = self.parsed_store.get(uri) {
            let diagnostics: Vec<(PurlRange, VulnerabilityInformation)> = parsed_content
                .ranges
                .into_iter()
                .filter_map(|(direct_dependency, range)| {
                    if let Some((purl, info)) = self.security_display_store.get(&direct_dependency)
                    {
                        let purl_range = PurlRange { purl, range };
                        Some((purl_range, info.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            return diagnostics;
        }
        vec![]
    }

    pub(crate) fn store_document(&self, uri: &Url, text_document: String) {
        self.document_store.insert(uri, text_document);
    }
}
