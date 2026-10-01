// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{
    AppError, Result,
    planner::{ActiveProfile, AggregatePlan},
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    pub profiles: Vec<ProfileStatus>,
    pub dns_owner: Option<String>,
    pub shadowed_dns: Vec<String>,
    pub recovery_pending: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileStatus {
    pub name: String,
    pub priority: i32,
    pub interface: String,
    pub state: ProfileState,
    pub dns: DnsState,
    pub routes: Vec<RouteStatus>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileState {
    Connected,
    Reconnecting,
    Standby,
    RecoveryPending,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsState {
    Owner,
    Shadowed { by: String },
    None,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouteStatus {
    pub cidr: String,
    pub installed: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub blocked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadowed_by: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl StatusReport {
    pub fn mark_reconnecting(&mut self) {
        for profile in &mut self.profiles {
            if profile.state == ProfileState::Connected {
                profile.state = ProfileState::Reconnecting;
            }
            // Do not claim planned routes are installed after failed verification.
            for route in &mut profile.routes {
                route.installed = false;
            }
        }
    }

    // A persisted report is historical once its supervisor is unreachable.
    // Unprivileged status clients cannot inspect the root-only journal, so a
    // cached connected/standby profile must itself imply pending recovery.
    pub fn supervisor_unavailable(&mut self, journal_dirty: bool) {
        self.recovery_pending |= journal_dirty || !self.profiles.is_empty();
        for profile in &mut self.profiles {
            profile.state = ProfileState::RecoveryPending;
            for route in &mut profile.routes {
                route.installed = false;
            }
        }
    }

    #[must_use]
    pub fn build(active: &[ActiveProfile], plan: &AggregatePlan, recovery_pending: bool) -> Self {
        let shadowed: HashMap<_, _> = plan
            .shadowed_routes
            .iter()
            .map(|route| ((route.profile.as_str(), route.prefix), route.owner.as_str()))
            .collect();
        let blocked: HashSet<_> = plan.blocked_routes.iter().copied().collect();
        let dns_owner = plan.dns.as_ref().map(|dns| dns.owner.clone());
        let mut profiles: Vec<_> = active
            .iter()
            .map(|profile| {
                let routes: Vec<_> = profile
                    .allowed_routes
                    .iter()
                    .map(|route| {
                        let owner = shadowed
                            .get(&(profile.name.as_str(), *route))
                            .map(|owner| (*owner).to_owned());
                        let is_blocked = owner.is_none() && blocked.contains(route);
                        RouteStatus {
                            cidr: route.to_string(),
                            installed: owner.is_none() && !is_blocked,
                            blocked: is_blocked,
                            shadowed_by: owner,
                        }
                    })
                    .collect();
                let dns = if dns_owner.as_deref() == Some(profile.name.as_str()) {
                    DnsState::Owner
                } else if !profile.dns_servers.is_empty() {
                    DnsState::Shadowed {
                        by: dns_owner.clone().unwrap_or_default(),
                    }
                } else {
                    DnsState::None
                };
                let state = if dns == DnsState::Owner
                    || routes.iter().any(|route| route.installed || route.blocked)
                {
                    ProfileState::Connected
                } else {
                    ProfileState::Standby
                };
                ProfileStatus {
                    name: profile.name.clone(),
                    priority: profile.priority,
                    interface: profile.interface.clone(),
                    state,
                    dns,
                    routes,
                }
            })
            .collect();
        profiles.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.name.cmp(&right.name))
        });
        Self {
            profiles,
            dns_owner,
            shadowed_dns: plan.shadowed_dns.clone(),
            recovery_pending,
        }
    }

    #[must_use]
    pub fn select(&self, name: Option<&str>) -> Self {
        let profiles = match name {
            Some(name) => self
                .profiles
                .iter()
                .filter(|profile| profile.name == name)
                .cloned()
                .collect(),
            None => self.profiles.clone(),
        };
        Self {
            profiles,
            dns_owner: self.dns_owner.clone(),
            shadowed_dns: self.shadowed_dns.clone(),
            recovery_pending: self.recovery_pending,
        }
    }
}

pub fn write_atomic(path: &Path, report: &StatusReport) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Runtime("status path has no parent".to_owned()))?;
    crate::secure_fs::ensure_directory(parent, 0o755)
        .map_err(|error| AppError::Runtime(format!("cannot secure status directory: {error}")))?;
    let bytes = serde_json::to_vec(report)
        .map_err(|error| AppError::Runtime(format!("cannot serialize status: {error}")))?;
    crate::secure_fs::write_atomic(path, &bytes, 0o644)
        .map_err(|error| AppError::Runtime(format!("cannot publish status: {error}")))?;
    if read(path)? != *report {
        return Err(AppError::Runtime(
            "system write verification failed: published status does not match requested state"
                .to_owned(),
        ));
    }
    Ok(())
}

pub fn read(path: &Path) -> Result<StatusReport> {
    read_if_present(path)?
        .ok_or_else(|| AppError::Ipc("supervisor status file is missing".to_owned()))
}

pub fn read_if_present(path: &Path) -> Result<Option<StatusReport>> {
    let bytes = match crate::secure_fs::read(path, 0o644, crate::secure_fs::MAX_STATE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(AppError::Ipc(format!(
                "cannot read supervisor status: {error}"
            )));
        }
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| AppError::Ipc(format!("cannot decode supervisor status: {error}")))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    #[test]
    fn offline_status_never_claims_cached_tunnels_are_connected() {
        for state in [
            ProfileState::Connected,
            ProfileState::Reconnecting,
            ProfileState::Standby,
        ] {
            let mut report = StatusReport {
                profiles: vec![ProfileStatus {
                    name: "work".into(),
                    priority: 0,
                    interface: "utun8".into(),
                    state,
                    dns: DnsState::None,
                    routes: vec![RouteStatus {
                        cidr: "10.0.0.0/8".into(),
                        installed: true,
                        blocked: false,
                        shadowed_by: None,
                    }],
                }],
                ..StatusReport::default()
            };
            // The journal is unreadable by ordinary users, even after a crash.
            report.supervisor_unavailable(false);
            assert!(report.recovery_pending);
            assert_eq!(report.profiles[0].state, ProfileState::RecoveryPending);
            assert!(!report.profiles[0].routes[0].installed);
        }
        let mut empty = StatusReport::default();
        empty.supervisor_unavailable(false);
        assert!(!empty.recovery_pending);
        empty.supervisor_unavailable(true);
        assert!(empty.recovery_pending);
        empty.supervisor_unavailable(false);
        assert!(empty.recovery_pending);
    }

    #[test]
    fn failed_route_refresh_reports_reconnecting_without_claiming_installed_routes() {
        let mut report = StatusReport {
            profiles: vec![ProfileStatus {
                name: "work".into(),
                priority: 0,
                interface: "utun8".into(),
                state: ProfileState::Connected,
                dns: DnsState::Owner,
                routes: vec![RouteStatus {
                    cidr: "0.0.0.0/0".into(),
                    installed: true,
                    blocked: false,
                    shadowed_by: None,
                }],
            }],
            ..StatusReport::default()
        };
        report.mark_reconnecting();
        let selected = report.select(Some("work"));
        assert_eq!(selected.profiles[0].state, ProfileState::Reconnecting);
        assert!(!selected.profiles[0].routes[0].installed);
        assert!(!selected.recovery_pending);
        let json = serde_json::to_string(&selected).unwrap();
        assert!(json.contains("\"state\":\"reconnecting\""));
        assert_eq!(
            serde_json::from_str::<StatusReport>(&json).unwrap(),
            selected
        );
    }

    #[test]
    fn missing_cache_is_distinct_from_corrupt_or_unsafe_cache() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        assert!(read_if_present(&path).unwrap().is_none());
        fs::write(&path, b"invalid json").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_if_present(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_if_present(&path).is_err());
    }

    #[test]
    fn atomic_status_write_is_verified() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = directory.path().join("status.json");
        let report = StatusReport::default();
        write_atomic(&path, &report).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            read(&path).unwrap_or_else(|error| panic!("{error}")),
            report
        );
        assert_eq!(
            fs::metadata(path)
                .unwrap_or_else(|error| panic!("{error}"))
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }
}
