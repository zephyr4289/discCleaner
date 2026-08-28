use crate::classify::BlockTree;
use std::collections::{HashSet, VecDeque};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DangerHop {
    pub dev_name: String,
    pub edge_type: String,
    pub dm_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DangerPath {
    pub hops: Vec<DangerHop>,
    pub terminal_class: String,
    pub terminal_detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalkOutcome {
    Clean,
    Danger(Vec<DangerPath>),
    DepthExceeded { at: Vec<String> },
}

pub struct BlockGraph<'a> {
    tree: &'a BlockTree,
}

impl<'a> BlockGraph<'a> {
    pub fn new(tree: &'a BlockTree) -> Self {
        Self { tree }
    }

    /// Pure upward danger traversal from target_name (Δ199, Δ204).
    /// Follows target -> holders -> holders-of-holders -> live terminals (mounts, swap, active system).
    /// Cycle-safe (visited set) and depth-capped (default max_depth = 16).
    pub fn live_dangers(&self, target_name: &str, max_depth: usize) -> WalkOutcome {
        let mut visited = HashSet::new();
        let mut dangers = Vec::new();

        // Queue contains (current_node_name, path_so_far)
        let mut queue = VecDeque::new();
        queue.push_back((target_name.to_string(), Vec::new()));
        visited.insert(target_name.to_string());

        while let Some((current_name, path)) = queue.pop_front() {
            if path.len() >= max_depth {
                return WalkOutcome::DepthExceeded {
                    at: vec![current_name],
                };
            }

            if let Some(node) = self.tree.nodes.get(&current_name) {
                // If not root of search, check if current node has live terminals
                if !path.is_empty() {
                    if !node.mounts.is_empty() {
                        dangers.push(DangerPath {
                            hops: path.clone(),
                            terminal_class: "MOUNTED".to_string(),
                            terminal_detail: node.mounts.join(", "),
                        });
                    }

                    if node.swap_active {
                        dangers.push(DangerPath {
                            hops: path.clone(),
                            terminal_class: "SWAP".to_string(),
                            terminal_detail: format!("Active swap on {}", node.name),
                        });
                    }
                }

                // Traverse upward edges (holders)
                for holder in &node.holders {
                    if !visited.contains(holder) {
                        visited.insert(holder.clone());
                        let mut next_path = path.clone();
                        next_path.push(DangerHop {
                            dev_name: holder.clone(),
                            edge_type: "holder".to_string(),
                            dm_type: if node.active_crypt {
                                Some("crypt".to_string())
                            } else if node.active_lvm {
                                Some("lvm".to_string())
                            } else {
                                None
                            },
                        });
                        queue.push_back((holder.clone(), next_path));
                    }
                }
            }
        }

        if dangers.is_empty() {
            WalkOutcome::Clean
        } else {
            WalkOutcome::Danger(dangers)
        }
    }
}
