use std::collections::HashMap;

use crate::server::purl::Purl;

struct Project<'a> {
    pub dependencies: HashMap<String, &'a Dependency<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
struct Dependency<'a> {
    purl: Purl,
    children: Vec<&'a Dependency<'a>>,
}

impl<'a> Dependency<'a> {
    fn add_child(&mut self, child: &'a mut Dependency) {
        self.children.push(child);
    }

    fn add_children(&mut self, children: &mut Vec<&'a Dependency<'a>>) {
        self.children.append(children);
    }
}

#[cfg(test)]
mod test {
    use crate::server::purl::Purl;

    use super::Dependency;

    #[test]
    fn can_construct_dependency_graph() {
        let mut root = Dependency {
            purl: Purl {
                package: "pkg".to_string(),
                group_id: Some("group".to_string()),
                artifact_id: "artifact".to_string(),
                version: "1.0.0".to_string(),
                purl_type: None,
            },
            children: vec![],
        };

        let child1 = Dependency {
            purl: Purl {
                package: "pkg".to_string(),
                group_id: Some("group".to_string()),
                artifact_id: "artifact".to_string(),
                version: "1.0.0".to_string(),
                purl_type: None,
            },
            children: vec![],
        };
        let child2 = Dependency {
            purl: Purl {
                package: "pkg".to_string(),
                group_id: Some("group".to_string()),
                artifact_id: "artifact".to_string(),
                version: "1.0.0".to_string(),
                purl_type: None,
            },
            children: vec![],
        };

        let mut children = vec![&child1, &child2];

        root.add_children(&mut children);

        assert_eq!(root.children.len(), 2);
    }
}
