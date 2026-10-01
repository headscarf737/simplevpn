// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{AppError, Result, planner::PlannedRoute};

pub const JOURNAL_VERSION: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryJournal {
    pub version: u8,
    pub dirty: bool,
    pub stage: TransitionStage,
    pub dns_snapshot: Option<DnsSnapshot>,
    pub routes: Vec<JournalRoute>,
    pub pf_anchor_installed: bool,
    #[serde(default)]
    pub pf_was_enabled: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionStage {
    Clean,
    Prepared,
    Interface,
    EndpointRoutes,
    AggregateRoutes,
    Firewall,
    Dns,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsSnapshot {
    pub services: Vec<DnsServiceSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsServiceSnapshot {
    pub path: String,
    pub existed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_order: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_timeout: Option<i32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sort_list: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supplemental_match_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supplemental_match_orders: Vec<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JournalRoute {
    pub prefix: String,
}

impl RecoveryJournal {
    #[must_use]
    pub fn clean() -> Self {
        Self {
            version: JOURNAL_VERSION,
            dirty: false,
            stage: TransitionStage::Clean,
            dns_snapshot: None,
            routes: Vec::new(),
            pf_anchor_installed: false,
            pf_was_enabled: None,
        }
    }

    pub fn record_routes(&mut self, routes: &[PlannedRoute]) {
        self.routes = routes
            .iter()
            .map(|route| JournalRoute {
                prefix: route.prefix.to_string(),
            })
            .collect();
    }
}

#[derive(Clone, Debug)]
pub struct JournalStore {
    path: PathBuf,
}

impl JournalStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> Result<Option<RecoveryJournal>> {
        let bytes =
            match crate::secure_fs::read(&self.path, 0o600, crate::secure_fs::MAX_STATE_BYTES) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(AppError::Runtime(format!(
                        "cannot read recovery journal {}: {error}",
                        self.path.display()
                    )));
                }
            };
        let journal: RecoveryJournal = serde_json::from_slice(&bytes).map_err(|error| {
            AppError::Runtime(format!(
                "cannot decode recovery journal {}: {error}",
                self.path.display()
            ))
        })?;
        if journal.version != JOURNAL_VERSION {
            return Err(AppError::Runtime(format!(
                "unsupported recovery journal version {}",
                journal.version
            )));
        }
        Ok(Some(journal))
    }

    pub fn save(&self, journal: &RecoveryJournal) -> Result<()> {
        let directory = self
            .path
            .parent()
            .ok_or_else(|| AppError::Runtime("journal path has no parent".to_owned()))?;
        crate::secure_fs::ensure_directory(directory, 0o700).map_err(|error| {
            AppError::Runtime(format!("cannot secure recovery directory: {error}"))
        })?;
        let bytes = serde_json::to_vec(journal).map_err(|error| {
            AppError::Runtime(format!("cannot serialize recovery journal: {error}"))
        })?;
        crate::secure_fs::write_atomic(&self.path, &bytes, 0o600).map_err(|error| {
            AppError::Runtime(format!("cannot publish recovery journal: {error}"))
        })?;
        if self.load()?.as_ref() != Some(journal) {
            return Err(verification_error(
                "published recovery journal does not match the requested state",
            ));
        }
        Ok(())
    }
}

fn verification_error(message: impl Into<String>) -> AppError {
    AppError::Runtime(format!(
        "system write verification failed: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use super::*;

    #[test]
    fn journal_is_sanitized_and_round_trips() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = JournalStore::new(directory.path().join("recovery.json"));
        let mut journal = RecoveryJournal::clean();
        journal.dirty = true;
        journal.dns_snapshot = Some(DnsSnapshot {
            services: vec![DnsServiceSnapshot {
                path: "State:/Network/Service/example/DNS".to_owned(),
                existed: true,
                server_addresses: vec!["192.0.2.53".to_owned()],
                search_domains: Vec::new(),
                domain_name: None,
                options: None,
                server_port: None,
                search_order: None,
                server_timeout: None,
                sort_list: Vec::new(),
                supplemental_match_domains: Vec::new(),
                supplemental_match_orders: Vec::new(),
            }],
        });
        journal.stage = TransitionStage::Dns;
        store
            .save(&journal)
            .unwrap_or_else(|error| panic!("{error}"));
        let text = fs::read_to_string(&store.path).unwrap_or_else(|error| panic!("{error}"));
        assert!(!text.contains("private_key"));
        assert!(!text.contains("preshared_key"));
        assert!(!text.contains("profiles"));
        assert!(!text.contains("target"));
        assert_eq!(
            store.load().unwrap_or_else(|error| panic!("{error}")),
            Some(journal)
        );
        let metadata = fs::metadata(&store.path).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn obsolete_journal_fields_are_ignored() {
        let old = r#"{
            "version": 1,
            "dirty": true,
            "stage": "aggregate_routes",
            "dns_snapshot": null,
            "routes": [{"prefix": "0.0.0.0/0", "target": "PhysicalDefault"}],
            "pf_anchor_installed": false,
            "pf_was_enabled": null,
            "profiles": [{"name": "old", "priority": 1, "interface": "utun9"}]
        }"#;
        let journal: RecoveryJournal =
            serde_json::from_str(old).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(journal.routes[0].prefix, "0.0.0.0/0");
    }

    #[test]
    fn clean_journal_has_no_runtime_material() {
        let clean = RecoveryJournal::clean();
        assert!(!clean.dirty);
        assert!(clean.routes.is_empty());
        assert!(clean.dns_snapshot.is_none());
    }

    #[test]
    fn recovery_rejects_symlinks_and_insecure_files_before_loading_routes() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.json");
        let store = JournalStore::new(&target);
        store.save(&RecoveryJournal::clean()).unwrap();
        let link = directory.path().join("recovery.json");
        symlink(&target, &link).unwrap();
        assert!(JournalStore::new(link).load().is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(store.load().is_err());
    }

    #[test]
    fn stale_temporary_symlink_does_not_affect_journal_write() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let target = directory.path().join("unrelated");
        fs::write(&target, "unchanged").unwrap_or_else(|error| panic!("{error}"));
        symlink(&target, directory.path().join("recovery.json.tmp"))
            .unwrap_or_else(|error| panic!("{error}"));
        let store = JournalStore::new(directory.path().join("recovery.json"));
        store.save(&RecoveryJournal::clean()).unwrap();
        assert_eq!(
            fs::read_to_string(target).unwrap_or_else(|error| panic!("{error}")),
            "unchanged"
        );
    }
}
