use std::path::PathBuf;

#[derive(Debug)]
pub struct WorkshopItem {
    pub path: PathBuf,
    pub id: u64,
    pub enabled: Option<bool>,
}

// We don't want to derive this as we don't want enabled to be checked
impl PartialEq for WorkshopItem {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.id == other.id
    }
}
