use std::path::PathBuf;

#[derive(Debug)]
pub struct WorkshopItem {
    pub path: PathBuf,
    pub id: u64,
    pub enabled: Option<bool>,
}
