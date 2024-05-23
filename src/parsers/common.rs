use crate::lsp::document_store::{BuildDependencies, MetadataDependencies, PurlRange};

pub fn combine_parsed_with_command_result(parsed: Vec<PurlRange>, cmd_result: BuildDependencies) -> MetadataDependencies {

    dbg!("parsed {}", &parsed.len());
    dbg!("cmd {}", &cmd_result.len());
    dbg!("-------------");
    dbg!("{}", &parsed);
    dbg!("{}", &cmd_result);

    parsed
        .iter()
        .filter(|item| cmd_result.contains_key(&item.purl))
        .map(|item| {
            let purl_list = cmd_result.get(&item.purl).expect("none values already filtered out");
            let cloned_purl = item.purl.clone();
            (item.clone(), [vec![cloned_purl], purl_list.to_vec()].concat())
        })
        .collect()
}