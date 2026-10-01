// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::journal::DnsSnapshot;
use crate::supervisor::operations::TunnelParameters;
use crate::supervisor::state::{NetworkState, Protection};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Call {
    Resolve,
    Start,
    Stop,
    PrepareFirewall,
    FirewallApply,
    FirewallVerify,
    StateCleanup,
    PrepareRoutes,
    Routes,
    Dns,
    Journal,
    RemoveFirewall,
    Recover,
    Orphans,
}

struct FakeNetwork {
    now: Instant,
    calls: Vec<Call>,
    // Fail the nth occurrence of the next specified operation, then move on.
    faults: VecDeque<(Call, usize)>,
    protected: bool,
    verified: bool,
    routes: Vec<PlannedRoute>,
    dns_owner: Option<String>,
    persisted: Option<RecoveryJournal>,
    firewall: FirewallPlan,
    startup_policies: Vec<FirewallPlan>,
    start_failure_stage: FailureStage,
}

impl FakeNetwork {
    fn new() -> Self {
        Self {
            now: Instant::now(),
            calls: vec![],
            faults: VecDeque::new(),
            protected: false,
            verified: false,
            routes: vec![],
            dns_owner: None,
            persisted: None,
            firewall: FirewallPlan::default(),
            startup_policies: vec![],
            start_failure_stage: FailureStage::Interface,
        }
    }
    fn fail(&mut self, call: Call) {
        self.faults.push_back((call, 1));
    }
    fn trip(&mut self, call: Call) -> Result<()> {
        self.calls.push(call);
        if let Some((operation, remaining)) = self.faults.front_mut()
            && *operation == call
        {
            *remaining -= 1;
            if *remaining == 0 {
                self.faults.pop_front();
                return Err(AppError::Runtime(
                    "injected failure (no classification in text)".into(),
                ));
            }
        }
        Ok(())
    }
}

impl NetworkOperations for FakeNetwork {
    type Tunnel = ActiveProfile;
    fn now(&self) -> Instant {
        self.now
    }
    async fn resolve_tunnel(&mut self, profile: Profile) -> OperationResult<TunnelParameters> {
        self.trip(Call::Resolve)
            .map_err(Failure::at(FailureStage::Interface))?;
        Ok(TunnelParameters {
            profile,
            endpoints: vec!["192.0.2.1:51820".parse().unwrap()],
        })
    }
    async fn start_tunnel(
        &mut self,
        parameters: TunnelParameters,
    ) -> OperationResult<Self::Tunnel> {
        assert!(
            self.protected && self.verified,
            "tunnel started before protection verification"
        );
        assert!(self.persisted.as_ref().unwrap().pf_anchor_installed);
        self.startup_policies.push(self.firewall.clone());
        self.trip(Call::Start)
            .map_err(Failure::at(self.start_failure_stage))?;
        let TunnelParameters { profile, endpoints } = parameters;
        Ok(ActiveProfile {
            name: profile.name.clone(),
            priority: profile.priority,
            dns_priority: profile.dns_priority(),
            interface: format!("utun{}", profile.priority + 10),
            interface_addresses: profile.interface.addresses.clone(),
            allowed_routes: profile.allowed_routes().collect(),
            endpoints,
            dns_servers: profile
                .dns
                .as_ref()
                .map_or_else(Vec::new, |dns| dns.servers.clone()),
            dns_search_domains: vec![],
        })
    }
    fn active_profile(tunnel: &Self::Tunnel) -> ActiveProfile {
        tunnel.clone()
    }
    async fn stop_tunnel(&mut self, _: &mut Self::Tunnel) -> Result<()> {
        self.trip(Call::Stop)
    }
    fn dns_snapshot(&self) -> Result<DnsSnapshot> {
        Ok(DnsSnapshot::default())
    }
    fn save_journal(&mut self, _: &JournalStore, journal: &RecoveryJournal) -> Result<()> {
        self.trip(Call::Journal)?;
        self.persisted = Some(journal.clone());
        Ok(())
    }
    fn prepare_firewall(&mut self) -> Result<()> {
        self.trip(Call::PrepareFirewall)
    }
    fn pf_original_state(&self) -> Option<bool> {
        Some(false)
    }
    fn apply_firewall(&mut self, policy: &FirewallPlan) -> OperationResult {
        self.verified = false;
        if !policy.is_active() {
            self.protected = false; // Model a partial removal before a cleanup failure.
            return self
                .trip(Call::RemoveFirewall)
                .map_err(Failure::at(FailureStage::Cleanup));
        }
        self.trip(Call::FirewallApply)
            .map_err(Failure::at(FailureStage::FirewallApply))?;
        self.protected = true;
        self.firewall = policy.clone();
        self.trip(Call::FirewallVerify)
            .map_err(Failure::at(FailureStage::FirewallVerify))?;
        self.trip(Call::StateCleanup)
            .map_err(Failure::at(FailureStage::StateCleanup))?;
        self.verified = true;
        Ok(())
    }
    async fn prepare_routes(&mut self, _: &[PlannedRoute]) -> Result<()> {
        self.trip(Call::PrepareRoutes)
    }
    async fn apply_routes(&mut self, routes: &[PlannedRoute]) -> Result<()> {
        // Explicit supervisor route commands must follow the protection check.
        // This fake does not model Talpid's independent route maintenance.
        assert!(
            !self.protected || self.verified,
            "supervisor route command behind unverified protection"
        );
        self.trip(Call::Routes)?;
        self.routes = routes.to_vec();
        Ok(())
    }
    fn apply_dns(&mut self, plan: &AggregatePlan) -> Result<()> {
        self.trip(Call::Dns)?;
        self.dns_owner = plan.dns.as_ref().map(|dns| dns.owner.clone());
        Ok(())
    }
    async fn recover_stale(&mut self, _: &RecoveryJournal) -> Result<()> {
        self.trip(Call::Recover)?;
        self.routes.clear();
        self.dns_owner = None;
        Ok(())
    }
    fn cleanup_orphaned_firewall(&mut self) -> Result<()> {
        self.trip(Call::Orphans)
    }
    fn cleanup_recovered_firewall(&mut self, _: &RecoveryJournal) -> Result<()> {
        self.trip(Call::RemoveFirewall)?;
        self.protected = false;
        Ok(())
    }
}

fn profile(name: &str, priority: i32) -> Profile {
    serde_json::from_value(serde_json::json!({
        "version": 1, "name": name, "priority": priority,
        "interface": { "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "addresses": [format!("10.0.{priority}.2/32")] },
        "dns": { "servers": [format!("10.0.{priority}.1")] },
        "peers": [{ "public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", "endpoint": "192.0.2.1:51820", "allowed_ips": ["0.0.0.0/0"] }]
    })).unwrap()
}

fn supervisor(path: &Path, dirty: bool) -> Supervisor<'_, FakeNetwork> {
    let mut journal = RecoveryJournal::clean();
    journal.dirty = dirty;
    Supervisor {
        runtime: FakeNetwork::new(),
        tunnels: HashMap::new(),
        pending_cleanup: vec![],
        cleanup_guard: None,
        journal_store: JournalStore::new(path.with_extension("journal")),
        journal,
        status_path: path,
        machine: Machine::new(dirty),
    }
}

async fn retry(supervisor: &mut Supervisor<'_, FakeNetwork>) {
    supervisor.runtime.now = supervisor.machine.deadline().unwrap();
    supervisor.refresh_routes().await;
}

#[tokio::test]
async fn connecting_guard_is_verified_and_journaled_before_interface_creation() {
    for existing in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, false);
        if existing {
            let mut split = profile("split", 1);
            split.peers[0].allowed_ips = vec!["10.0.1.0/24".parse().unwrap()];
            supervisor.up(split).await.unwrap();
        }
        supervisor.runtime.calls.clear();
        supervisor.up(profile("full", 2)).await.unwrap();
        let calls = &supervisor.runtime.calls;
        let index = |call| calls.iter().position(|actual| *actual == call).unwrap();
        assert!(index(Call::Resolve) < index(Call::FirewallApply));
        assert!(index(Call::StateCleanup) < index(Call::Start));
        assert!(index(Call::Start) < index(Call::Routes));
        let guard = supervisor.runtime.startup_policies.last().unwrap();
        assert!(guard.full_lockdown);
        assert!(
            guard
                .rules
                .contains(&crate::firewall::FirewallRule::BlockAllOutbound)
        );
        assert!(guard.rules.iter().all(|rule| match rule {
            crate::firewall::FirewallRule::AllowTunnel { interface }
            | crate::firewall::FirewallRule::AllowTunnelNetwork { interface, .. } =>
                interface != "utun12",
            _ => true,
        }));
    }
}

#[tokio::test]
async fn connecting_firewall_failures_never_start_a_tunnel() {
    for call in [
        Call::PrepareFirewall,
        Call::FirewallApply,
        Call::FirewallVerify,
        Call::StateCleanup,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, false);
        supervisor.runtime.fail(call);
        supervisor.runtime.fail(call); // Also prevent rollback from verifying protection.
        assert!(supervisor.up(profile("full", 1)).await.is_err());
        assert!(!supervisor.runtime.calls.contains(&Call::Start));
        assert!(!supervisor.runtime.calls.contains(&Call::Routes));
        assert!(!supervisor.runtime.calls.contains(&Call::Dns));
        assert!(!supervisor.runtime.calls.contains(&Call::RemoveFirewall));
        assert!(supervisor.machine.recovery_required());
    }
}

#[tokio::test]
async fn connecting_journal_failures_never_start_unrecorded_resources() {
    // Prepared journal, pre-firewall intent, post-verification persistence.
    for write in 1..=3 {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, false);
        supervisor.runtime.faults.push_back((Call::Journal, write));
        assert!(supervisor.up(profile("full", 1)).await.is_err());
        assert!(!supervisor.runtime.calls.contains(&Call::Start));
        assert!(!supervisor.runtime.calls.contains(&Call::Routes));
        assert!(supervisor.machine.recovery_required());
        if write == 3 {
            assert!(supervisor.runtime.protected);
        }
    }
}

#[tokio::test]
async fn failed_start_or_rollback_cleanup_retains_connecting_lockdown() {
    for incomplete_start in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, false);
        let mut split = profile("split", 1);
        split.peers[0].allowed_ips = vec!["10.0.1.0/24".parse().unwrap()];
        supervisor.up(split).await.unwrap();
        if incomplete_start {
            supervisor.runtime.start_failure_stage = FailureStage::Cleanup;
            supervisor.runtime.fail(Call::Start);
        } else {
            supervisor.runtime.fail(Call::Dns);
            supervisor.runtime.fail(Call::Stop);
        }
        assert!(supervisor.up(profile("full", 2)).await.is_err());
        assert!(supervisor.machine.recovery_required());
        assert!(supervisor.runtime.firewall.full_lockdown);
        assert!(supervisor.cleanup_guard.as_ref().unwrap().full_lockdown);
        // A later failure removing PF must reassert the stronger connecting guard.
        supervisor.runtime.fail(Call::RemoveFirewall);
        assert!(supervisor.down_all().await.is_err());
        assert!(supervisor.runtime.protected);
        assert!(supervisor.runtime.firewall.full_lockdown);
        supervisor.down_all().await.unwrap();
        assert_eq!(supervisor.machine.status().state, NetworkState::Idle);
    }
}

#[tokio::test]
async fn firewall_faults_block_supervisor_route_commands_until_verification() {
    for (call, stage) in [
        (Call::PrepareFirewall, FailureStage::FirewallApply),
        (Call::FirewallApply, FailureStage::FirewallApply),
        (Call::FirewallVerify, FailureStage::FirewallVerify),
        (Call::StateCleanup, FailureStage::StateCleanup),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, false);
        supervisor.up(profile("work", 1)).await.unwrap();
        supervisor.event(StateEvent::NetworkChanged);
        supervisor.runtime.calls.clear();
        supervisor.runtime.fail(call);
        retry(&mut supervisor).await;
        assert_eq!(supervisor.machine.status().state, NetworkState::Blocked);
        assert_eq!(supervisor.machine.status().reason, Some(stage));
        assert_eq!(supervisor.machine.protection, Protection::Unverified);
        assert!(!supervisor.runtime.calls.contains(&Call::Routes));
        assert!(!supervisor.runtime.calls.contains(&Call::Dns));
        assert!(!supervisor.runtime.calls.contains(&Call::RemoveFirewall));
        let report = supervisor.status(None).unwrap();
        assert!(report.recovery_pending);
        assert!(
            report
                .profiles
                .iter()
                .all(|profile| profile.routes.iter().all(|route| !route.installed))
        );
        assert!(supervisor.down("work").await.is_err());
        assert!(supervisor.up(profile("other", 2)).await.is_err());
        retry(&mut supervisor).await;
        assert_eq!(supervisor.machine.status().state, NetworkState::Ready);
        assert_eq!(supervisor.machine.protection, Protection::Verified);
        assert_eq!(supervisor.runtime.dns_owner.as_deref(), Some("work"));
    }
}

#[tokio::test]
async fn network_failures_back_off_while_commands_remain_available() {
    for call in [Call::PrepareRoutes, Call::Routes, Call::Dns] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, false);
        supervisor.up(profile("work", 1)).await.unwrap();
        supervisor.event(StateEvent::NetworkChanged);
        for seconds in [1, 2, 4, 8, 16, 30, 30] {
            supervisor.runtime.fail(call);
            retry(&mut supervisor).await;
            assert_eq!(
                supervisor.machine.deadline(),
                Some(supervisor.runtime.now + Duration::from_secs(seconds))
            );
            assert_eq!(supervisor.machine.status().state, NetworkState::Recovering);
            assert_eq!(supervisor.machine.protection, Protection::Verified);
            // Exercise actual command dispatch between attempts.
            let (_, report) = supervisor
                .dispatch(
                    Request::Status { name: None },
                    501,
                    &ControlAccess::default(),
                )
                .await
                .unwrap();
            assert!(!report.recovery_pending);
            assert_eq!(
                report.profiles[0].state,
                crate::status::ProfileState::Reconnecting
            );
            assert!(supervisor.runtime.protected);
        }
        supervisor
            .dispatch(Request::DownAll, 0, &ControlAccess::default())
            .await
            .unwrap();
        assert!(supervisor.machine.deadline().is_none());
        assert_eq!(supervisor.machine.status().state, NetworkState::Idle);
        let calls = supervisor.runtime.calls.clone();
        supervisor.refresh_routes().await;
        assert_eq!(supervisor.runtime.calls, calls);
    }
}

#[tokio::test]
async fn partial_profile_removal_during_recovery_reconciles_remaining_routes_and_dns() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.json");
    let mut supervisor = supervisor(&path, false);
    supervisor.up(profile("low", 1)).await.unwrap();
    supervisor.up(profile("high", 2)).await.unwrap();
    supervisor.event(StateEvent::NetworkChanged);
    supervisor.runtime.fail(Call::Routes);
    retry(&mut supervisor).await;
    supervisor.down("high").await.unwrap();
    assert_eq!(supervisor.machine.status().state, NetworkState::Ready);
    assert_eq!(supervisor.tunnels.len(), 1);
    assert_eq!(supervisor.runtime.dns_owner.as_deref(), Some("low"));
    assert_eq!(
        supervisor.runtime.routes,
        aggregate(&supervisor.active_profiles()).routes
    );
    assert!(supervisor.machine.deadline().is_none());
    assert!(supervisor.runtime.protected);
}

#[tokio::test]
async fn journal_faults_require_explicit_recovery_and_never_auto_retry() {
    // Every persistence boundary during refresh, including the final commit.
    for write in 1..=4 {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, false);
        supervisor.up(profile("work", 1)).await.unwrap();
        supervisor.event(StateEvent::NetworkChanged);
        supervisor.runtime.calls.clear();
        supervisor.runtime.faults.push_back((Call::Journal, write));
        retry(&mut supervisor).await;
        assert_eq!(
            supervisor.machine.status().reason,
            Some(FailureStage::Journal)
        );
        assert!(supervisor.machine.recovery_required());
        assert!(supervisor.machine.deadline().is_none());
        assert!(!supervisor.runtime.calls.contains(&Call::RemoveFirewall));
        assert!(supervisor.runtime.protected);
        assert!(supervisor.up(profile("other", 2)).await.is_err());
        supervisor.down_all().await.unwrap();
        assert_eq!(supervisor.machine.status().state, NetworkState::Idle);
        assert!(!supervisor.journal.dirty);
    }
}

#[tokio::test]
async fn requested_failure_returns_to_ready_only_after_verified_rollback() {
    for call in [
        Call::FirewallApply,
        Call::FirewallVerify,
        Call::StateCleanup,
        Call::Routes,
        Call::Dns,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, false);
        supervisor.up(profile("old", 1)).await.unwrap();
        supervisor.runtime.fail(call);
        assert!(supervisor.up(profile("new", 2)).await.is_err());
        assert_eq!(supervisor.machine.status().state, NetworkState::Ready);
        assert_eq!(supervisor.machine.protection, Protection::Verified);
        assert_eq!(supervisor.tunnels.len(), 1);
        assert!(supervisor.tunnels.contains_key("old"));
        assert_eq!(
            supervisor.runtime.routes,
            aggregate(&supervisor.active_profiles()).routes
        );
        assert_eq!(supervisor.runtime.dns_owner.as_deref(), Some("old"));
    }
}

#[tokio::test]
async fn rollback_failure_preserves_resources_and_stops_unsafe_mutations() {
    for call in [
        Call::FirewallApply,
        Call::FirewallVerify,
        Call::StateCleanup,
        Call::Routes,
        Call::Dns,
        Call::Stop,
        Call::Journal,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, false);
        supervisor.up(profile("old", 1)).await.unwrap();
        supervisor.runtime.fail(Call::Dns);
        supervisor.runtime.fail(call);
        supervisor.runtime.calls.clear();
        assert!(supervisor.up(profile("new", 2)).await.is_err());
        assert!(supervisor.machine.recovery_required());
        assert!(supervisor.machine.deadline().is_none());
        assert!(supervisor.runtime.protected);
        assert!(!supervisor.runtime.calls.contains(&Call::RemoveFirewall));
        if matches!(
            call,
            Call::FirewallApply | Call::FirewallVerify | Call::StateCleanup
        ) {
            let dns = supervisor
                .runtime
                .calls
                .iter()
                .position(|call| *call == Call::Dns)
                .unwrap();
            assert!(!supervisor.runtime.calls[dns + 1..].contains(&Call::Routes));
        }
        supervisor.down_all().await.unwrap();
        assert!(!supervisor.has_resources());
        assert_eq!(supervisor.machine.status().state, NetworkState::Idle);
    }
}

#[tokio::test]
async fn disconnect_cleanup_failure_keeps_guard_and_cleanup_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.json");
    let mut supervisor = supervisor(&path, false);
    supervisor.up(profile("work", 1)).await.unwrap();
    supervisor.event(StateEvent::NetworkChanged);
    supervisor.runtime.fail(Call::Stop);
    supervisor.runtime.calls.clear();
    assert!(supervisor.down_all().await.is_err());
    assert!(supervisor.machine.recovery_required());
    assert!(supervisor.machine.deadline().is_none());
    assert!(supervisor.runtime.protected);
    assert_eq!(supervisor.pending_cleanup.len(), 1);
    assert!(!supervisor.runtime.calls.contains(&Call::RemoveFirewall));
    supervisor.runtime.fail(Call::Stop);
    assert!(supervisor.down_all().await.is_err());
    assert!(supervisor.runtime.protected);
    supervisor.down_all().await.unwrap();
    assert!(!supervisor.has_resources());
    assert!(!supervisor.runtime.protected);
}

#[tokio::test]
async fn failed_final_firewall_removal_or_persistence_reasserts_guard() {
    // Count journal writes in a final disconnect to cover each boundary.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.json");
    let mut reference = supervisor(&path, false);
    reference.up(profile("work", 1)).await.unwrap();
    reference.runtime.calls.clear();
    reference.down_all().await.unwrap();
    let writes = reference
        .runtime
        .calls
        .iter()
        .filter(|call| **call == Call::Journal)
        .count();
    for fault in [
        (Call::RemoveFirewall, 1),
        (Call::Journal, writes - 1),
        (Call::Journal, writes),
    ] {
        let mut supervisor = supervisor(&path, false);
        supervisor.up(profile("work", 1)).await.unwrap();
        supervisor.runtime.faults.push_back(fault);
        assert!(supervisor.down_all().await.is_err());
        assert!(supervisor.runtime.protected);
        assert!(supervisor.machine.recovery_required());
        assert!(supervisor.journal.dirty);
        supervisor.down_all().await.unwrap();
        assert_eq!(supervisor.machine.protection, Protection::NotRequired);
    }
}

#[tokio::test]
async fn dirty_startup_and_failed_cleanup_remain_explicit() {
    for explicit_up in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, true);
        assert_eq!(supervisor.machine.protection, Protection::Unverified);
        supervisor.event(StateEvent::NetworkChanged);
        supervisor.refresh_routes().await;
        assert!(supervisor.runtime.calls.is_empty());
        supervisor.runtime.fail(Call::Recover);
        assert!(supervisor.down_all().await.is_err());
        assert!(!supervisor.runtime.calls.contains(&Call::RemoveFirewall));
        assert!(supervisor.journal.dirty);
        if explicit_up {
            supervisor.up(profile("work", 1)).await.unwrap();
            assert_eq!(supervisor.machine.status().state, NetworkState::Ready);
        } else {
            supervisor.down_all().await.unwrap();
            assert_eq!(supervisor.machine.status().state, NetworkState::Idle);
        }
    }
}

#[tokio::test]
async fn partial_disconnect_does_not_relax_full_protection_until_cleanup_succeeds() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.json");
    let mut supervisor = supervisor(&path, false);
    let mut split = profile("split", 1);
    split.peers[0].allowed_ips = vec!["10.0.1.0/24".parse().unwrap()];
    supervisor.up(split).await.unwrap();
    supervisor.up(profile("full", 2)).await.unwrap();
    assert!(supervisor.runtime.firewall.full_lockdown);
    supervisor.runtime.fail(Call::Stop);
    assert!(supervisor.down("full").await.is_err());
    assert!(supervisor.machine.recovery_required());
    assert!(supervisor.runtime.firewall.full_lockdown);
    assert!(supervisor.runtime.protected);
    supervisor.runtime.fail(Call::RemoveFirewall);
    assert!(supervisor.down_all().await.is_err());
    assert!(supervisor.runtime.firewall.full_lockdown);
    assert!(supervisor.runtime.protected);
    supervisor.down_all().await.unwrap();
    assert!(!supervisor.runtime.protected);
}

#[tokio::test]
async fn failed_interface_start_rolls_back_before_reporting_idle_or_ready() {
    for existing in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.json");
        let mut supervisor = supervisor(&path, false);
        if existing {
            supervisor.up(profile("old", 1)).await.unwrap();
        }
        supervisor.runtime.fail(Call::Start);
        assert!(supervisor.up(profile("new", 2)).await.is_err());
        assert_eq!(
            supervisor.machine.status().state,
            if existing {
                NetworkState::Ready
            } else {
                NetworkState::Idle
            }
        );
        assert_eq!(supervisor.journal.dirty, existing);
        assert!(!supervisor.tunnels.contains_key("new"));
        assert!(supervisor.machine.deadline().is_none());
    }
}

#[tokio::test]
async fn disconnect_all_cancels_retry_even_when_it_rolls_back_to_ready() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.json");
    let mut supervisor = supervisor(&path, false);
    supervisor.up(profile("work", 1)).await.unwrap();
    supervisor.event(StateEvent::NetworkChanged);
    supervisor.runtime.fail(Call::Routes);
    assert!(supervisor.down_all().await.is_err());
    assert_eq!(supervisor.machine.status().state, NetworkState::Ready);
    assert_eq!(supervisor.machine.protection, Protection::Verified);
    assert!(supervisor.machine.deadline().is_none());
    assert!(supervisor.runtime.protected);
    assert!(supervisor.tunnels.contains_key("work"));
    supervisor.runtime.fail(Call::Journal);
    assert!(supervisor.down_all().await.is_err());
    assert_eq!(
        supervisor.machine.status().reason,
        Some(FailureStage::Journal)
    );
    assert!(supervisor.machine.recovery_required());
    assert!(supervisor.machine.deadline().is_none());
}
