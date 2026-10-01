// SPDX-License-Identifier: GPL-3.0-or-later

use super::state::FailureStage;
use crate::{
    AppError, Result,
    config::Profile,
    firewall::FirewallPlan,
    journal::{DnsSnapshot, JournalStore, RecoveryJournal},
    planner::{ActiveProfile, AggregatePlan, PlannedRoute},
};
use std::net::SocketAddr;

#[derive(Debug)]
pub struct Failure {
    pub stage: FailureStage,
    pub error: AppError,
}

pub type OperationResult<T = ()> = std::result::Result<T, Failure>;

// Endpoint resolution creates no tunnel resources. The same resolved addresses
// are used by the connecting firewall and the device, avoiding a second lookup.
pub struct TunnelParameters {
    pub profile: Profile,
    pub endpoints: Vec<SocketAddr>,
}

impl Failure {
    pub fn new(stage: FailureStage, error: AppError) -> Self {
        Self { stage, error }
    }
    pub fn at(stage: FailureStage) -> impl FnOnce(AppError) -> Self {
        move |error| Self::new(stage, error)
    }
}

// The production adapter includes independent read-back verification in each
// operation. Tests replace it, including persistence and tunnel cleanup, so they
// exercise the actual supervisor orchestration without privileged mutations.
// This boundary covers explicit supervisor commands, not Talpid's autonomous
// route refreshes or cleanup. PF constrains traffic during those updates.
pub trait NetworkOperations {
    type Tunnel;
    fn now(&self) -> tokio::time::Instant {
        tokio::time::Instant::now()
    }
    async fn resolve_tunnel(&mut self, profile: Profile) -> OperationResult<TunnelParameters>;
    async fn start_tunnel(&mut self, parameters: TunnelParameters)
    -> OperationResult<Self::Tunnel>;
    fn active_profile(tunnel: &Self::Tunnel) -> ActiveProfile;
    async fn stop_tunnel(&mut self, tunnel: &mut Self::Tunnel) -> Result<()>;
    fn dns_snapshot(&self) -> Result<DnsSnapshot>;
    fn save_journal(&mut self, store: &JournalStore, journal: &RecoveryJournal) -> Result<()>;
    fn prepare_firewall(&mut self) -> Result<()>;
    fn pf_original_state(&self) -> Option<bool>;
    fn apply_firewall(&mut self, policy: &FirewallPlan) -> OperationResult;
    async fn prepare_routes(&mut self, routes: &[PlannedRoute]) -> Result<()>;
    async fn apply_routes(&mut self, routes: &[PlannedRoute]) -> Result<()>;
    fn apply_dns(&mut self, plan: &AggregatePlan) -> Result<()>;
    async fn recover_stale(&mut self, journal: &RecoveryJournal) -> Result<()>;
    fn cleanup_orphaned_firewall(&mut self) -> Result<()>;
    fn cleanup_recovered_firewall(&mut self, journal: &RecoveryJournal) -> Result<()>;
}

impl NetworkOperations for crate::platform::MacRuntime {
    type Tunnel = crate::platform::Tunnel;
    async fn resolve_tunnel(&mut self, profile: Profile) -> OperationResult<TunnelParameters> {
        crate::platform::Tunnel::resolve(profile).await
    }
    async fn start_tunnel(
        &mut self,
        parameters: TunnelParameters,
    ) -> OperationResult<Self::Tunnel> {
        self.start_tunnel(parameters).await
    }
    fn active_profile(tunnel: &Self::Tunnel) -> ActiveProfile {
        tunnel.active_profile()
    }
    async fn stop_tunnel(&mut self, tunnel: &mut Self::Tunnel) -> Result<()> {
        tunnel.stop().await
    }
    fn dns_snapshot(&self) -> Result<DnsSnapshot> {
        self.dns_snapshot()
    }
    fn save_journal(&mut self, store: &JournalStore, journal: &RecoveryJournal) -> Result<()> {
        store.save(journal)
    }
    fn prepare_firewall(&mut self) -> Result<()> {
        self.prepare_firewall()
    }
    fn pf_original_state(&self) -> Option<bool> {
        self.pf_original_state()
    }
    fn apply_firewall(&mut self, policy: &FirewallPlan) -> OperationResult {
        self.apply_firewall(policy)
    }
    async fn prepare_routes(&mut self, routes: &[PlannedRoute]) -> Result<()> {
        Self::prepare_routes(self, routes).await
    }
    async fn apply_routes(&mut self, routes: &[PlannedRoute]) -> Result<()> {
        self.apply_routes(routes).await
    }
    fn apply_dns(&mut self, plan: &AggregatePlan) -> Result<()> {
        self.apply_dns(plan)
    }
    async fn recover_stale(&mut self, journal: &RecoveryJournal) -> Result<()> {
        self.recover_stale(journal).await
    }
    fn cleanup_orphaned_firewall(&mut self) -> Result<()> {
        self.cleanup_orphaned_firewall()
    }
    fn cleanup_recovered_firewall(&mut self, journal: &RecoveryJournal) -> Result<()> {
        self.cleanup_recovered_firewall(journal)
    }
}
