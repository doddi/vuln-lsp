use std::process::Command;
use tracing::debug;

use crate::common::{purl::Purl, BuildDependencies};

pub fn build_dependency_list_from_command() -> anyhow::Result<BuildDependencies> {
    debug!("Building tree using mvn");

    let output = Command::new("mvn")
        .args(["dependency:tree", "-DoutputType=dot"])
        .output()
        .expect("failed to execute metadata command");

    // TODO: Check for error before continuing

    let display = String::from_utf8(output.stdout).unwrap();
    parse_response(display)
}

#[derive(Debug)]
struct TreeParse {
    state: DigraphState,
    application_purl: Option<Purl>,
    parent_and_child: Vec<(Purl, Purl)>,
}

impl TreeParse {
    fn new() -> Self {
        TreeParse {
            state: DigraphState::LookForStart,
            application_purl: None,
            parent_and_child: vec![],
        }
    }
}
#[derive(Debug, PartialEq)]
enum DigraphState {
    LookForStart,
    ParentChild,
    Finished,
}

fn parse_response(data: String) -> anyhow::Result<BuildDependencies> {
    let lines = data.lines();

    let mut tree: TreeParse = TreeParse::new();

    lines.for_each(|line| match tree.state {
        DigraphState::LookForStart => look_for_start_state(&mut tree, line),
        DigraphState::ParentChild => accumulate_parent_child(&mut tree, line),
        DigraphState::Finished => {}
    });

    debug!("{:?}", tree);
    match tree.state {
        DigraphState::Finished => calculate_build_dependencies(tree),
        _ => Err(anyhow::anyhow!("Error parsing dependency:tree call")),
    }
}

fn look_for_start_state(tree: &mut TreeParse, line: &str) {
    if line_stars_with_start_of_dig_graph(line) {
        let tokens: Vec<&str> = line.split('"').collect();
        if tokens.len() == 3 {
            if let Some(purl) = get_purl_from_digraph_string(tokens[1]) {
                tree.state = DigraphState::ParentChild;
                tree.application_purl = Some(purl);
            }
        }
    }
}

fn line_stars_with_start_of_dig_graph(line: &str) -> bool {
    let start_token = "[INFO] digraph";
    line.starts_with(start_token)
}

fn get_purl_from_digraph_string(line: &str) -> Option<Purl> {
    let tokens: Vec<&str> = line.split(":").collect();
    if tokens.len() >= 4 {
        return Some(Purl {
            package: "maven".to_string(),
            group_id: Some(tokens[0].to_string()),
            artifact_id: tokens[1].to_string(),
            version: tokens[3].to_string(),
            purl_type: Some(tokens[2].to_string()),
        });
    }
    None
}

fn accumulate_parent_child(tree: &mut TreeParse, line: &str) {
    let result = get_parent_child_from_digraph_line(line);
    match result {
        None => tree.state = DigraphState::Finished,
        Some(result) => tree.parent_and_child.push(result),
    }
}

fn get_parent_child_from_digraph_line(line: &str) -> Option<(Purl, Purl)> {
    let tokens: Vec<&str> = line.split("->").collect();
    if tokens.len() != 2 {
        return None;
    }
    let left: &str = tokens[0];
    let right: &str = tokens[1];

    // Left side needs to first strip [INFO]
    if let Some(left) = left.strip_prefix("[INFO]") {
        let left = left.trim();
        let left = &left[1..left.len() - 1];

        let right = &right[2..right.len() - 1];
        let right = right.trim();

        return match (
            get_purl_from_digraph_string(left),
            get_purl_from_digraph_string(right),
        ) {
            (Some(parent), Some(child)) => Some((parent, child)),
            (_, _) => None,
        };
    }

    None
}

fn calculate_build_dependencies(tree: TreeParse) -> anyhow::Result<BuildDependencies> {
    // Find direct dependencies
    let direct: Vec<&Purl> = tree
        .parent_and_child
        .iter()
        .filter(|value| value.0.eq(&tree.application_purl.clone().unwrap()))
        .map(|entity| &entity.1)
        .collect();

    let mut build_dependencies = BuildDependencies::new();

    direct.into_iter().for_each(|purl| {
        let mut list = Vec::new();
        find_all_dependencies_of(&tree, purl, &mut list);
        build_dependencies.insert(purl.clone(), list);
    });

    Ok(build_dependencies)
}

fn find_all_dependencies_of(tree: &TreeParse, purl: &Purl, dependencies: &mut Vec<Purl>) {
    // Add itself
    dependencies.push(purl.clone());

    // Find the children
    let children: Vec<Purl> = tree
        .parent_and_child
        .iter()
        .filter(|value| value.0.eq(purl))
        .map(|entity| entity.1.clone())
        .collect();

    children
        .iter()
        .for_each(|purl| find_all_dependencies_of(tree, purl, dependencies));
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_parent_child_into_build_dependencies() {
        let tree = TreeParse {
            state: DigraphState::Finished,
            application_purl: get_purl_from_digraph_string(
                "com.javatpoint.application1:my-application1:jar:1.0",
            ),
            parent_and_child: vec![
                (
                    get_purl_from_digraph_string(
                        "com.javatpoint.application1:my-application1:jar:1.0",
                    )
                    .unwrap(),
                    get_purl_from_digraph_string("org.opensaml:opensaml:jar:2.4.1:compile")
                        .unwrap(),
                ),
                (
                    get_purl_from_digraph_string(
                        "com.javatpoint.application1:my-application1:jar:1.0",
                    )
                    .unwrap(),
                    get_purl_from_digraph_string(
                        "org.apache.struts:struts-core:jar:1.3.10:compile",
                    )
                    .unwrap(),
                ),
                (
                    get_purl_from_digraph_string("org.opensaml:opensaml:jar:2.4.1:compile")
                        .unwrap(),
                    get_purl_from_digraph_string("org.opensaml:openws:jar:1.4.1:compile").unwrap(),
                ),
            ],
        };

        let result = calculate_build_dependencies(tree).unwrap();

        let key = Purl {
            package: "maven".to_string(),
            group_id: Some("org.apache.struts".to_string()),
            artifact_id: "struts-core".to_string(),
            version: "1.3.10".to_string(),
            purl_type: Some("jar".to_string()),
        };

        // 2 direct dependencies
        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&key));

        // opensaml has itself and a child dependency
        let key = Purl {
            package: "maven".to_string(),
            group_id: Some("org.opensaml".to_string()),
            artifact_id: "opensaml".to_string(),
            version: "2.4.1".to_string(),
            purl_type: Some("jar".to_string()),
        };

        assert_eq!(2, result.get(&key).unwrap().len());
    }

    #[test]
    fn can_get_parent_child_relationship() {
        let line = "[INFO] 	\"com.javatpoint.application1:my-application1:jar:1.0\" -> \"org.opensaml:opensaml:jar:2.4.1:compile\" ;";

        let result: (Purl, Purl) = get_parent_child_from_digraph_line(&line).unwrap();
    }

    #[test]
    fn can_get_purl_from_digrph_string() {
        let result =
            get_purl_from_digraph_string("com.javatpoint.application1:my-application1:jar:1.0");

        assert_eq!(
            result.unwrap(),
            Purl {
                package: "maven".to_string(),
                group_id: Some("com.javatpoint.application1".to_string()),
                artifact_id: "my-application1".to_string(),
                version: "1.0".to_string(),
                purl_type: Some("jar".to_string()),
            }
        )
    }

    #[test]
    fn should_move_to_start_state_if_start_found() {
        let mut tree: TreeParse = TreeParse::new();

        look_for_start_state(
            &mut tree,
            "[INFO] digraph \"com.javatpoint.application1:my-application1:jar:1.0\" {",
        );

        assert_eq!(tree.state, DigraphState::ParentChild);
        assert!(tree.application_purl.is_some());
    }

    #[test]
    fn should_not_move_to_start_state_if_start_not_found() {
        let mut tree: TreeParse = TreeParse::new();

        look_for_start_state(
            &mut tree,
            "INFO] digraph \"com.javatpoint.application1:my-application1:jar:1.0\" {",
        );

        assert_eq!(tree.state, DigraphState::LookForStart);
        assert!(tree.application_purl.is_none());
    }

    #[test]
    fn parse_file() {
        let data = include_str!("../../../resources/maven/dep_tree.txt");

        let result = parse_response(data.parse().unwrap()).unwrap();

        let key = Purl {
            package: "maven".to_string(),
            group_id: Some("org.apache.struts".to_string()),
            artifact_id: "struts-core".to_string(),
            version: "1.3.10".to_string(),
            purl_type: Some("jar".to_string()),
        };

        // 2 direct dependencies
        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&key));

        // opensaml has itself and a child dependency
        let key = Purl {
            package: "maven".to_string(),
            group_id: Some("org.opensaml".to_string()),
            artifact_id: "opensaml".to_string(),
            version: "2.4.1".to_string(),
            purl_type: Some("jar".to_string()),
        };

        assert_eq!(22, result.get(&key).unwrap().len());
    }
}
