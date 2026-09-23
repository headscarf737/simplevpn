// SPDX-License-Identifier: GPL-3.0-or-later

mod command;
mod dns_snapshot;
mod pf;
mod tunnel;
mod verify;

use std::collections::HashSet;

use futures::StreamExt;
use talpid_dns::{DnsConfig, DnsMonitor};
use talpid_routing::{NetNode, Node, RequiredRoute, RouteManagerHandle};
use tokio::time::{Duration, sleep};

use crate::{
    AppError, Result,
    error::format_error_chain,
    firewall::FirewallPlan,
    journal::{DnsSnapshot, RecoveryJournal},
    planner::{AggregatePlan, PlannedRoute, RouteTarget},
};

pub use tunnel::Tunnel;

pub struct MacRuntime {
    routes: RouteManagerHandle,
    dns: DnsMonitor,
    firewall: pf::PfController,
    route_changes: tokio::sync::mpsc::UnboundedReceiver<()>,
    applied_routes: Vec<PlannedRoute>,
    dns_baseline: Option<DnsSnapshot>,
}

impl MacRuntime {
    pub async fn new() -> Result<Self> {
        let routes = RouteManagerHandle::spawn()
            .await
            .map_err(|error| AppError::Platform(format!("cannot start Talpid routing: {error}")))?;
        let mut default_routes = routes.default_route_listener().await.map_err(|error| {
            AppError::Platform(format!("cannot monitor physical default routes: {error}"))
        })?;
        let (route_change_tx, route_changes) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while default_routes.next().await.is_some() {
                if route_change_tx.send(()).is_err() {
                    break;
                }
            }
        });
        let dns = DnsMonitor::new()
            .map_err(|error| AppError::Platform(format!("cannot start Talpid DNS: {error}")))?;
        let firewall = pf::PfController::new()?;
        Ok(Self {
            routes,
            dns,
            firewall,
            route_changes,
            applied_routes: Vec::new(),
            dns_baseline: None,
        })
    }

    pub async fn route_changed(&mut self) -> Option<()> {
        self.route_changes.recv().await
    }

    pub fn dns_snapshot(&self) -> Result<DnsSnapshot> {
        dns_snapshot::capture()
    }

    pub async fn apply_routes(&mut self, routes: &[PlannedRoute]) -> Result<()> {
        verify::reject_route_conflicts(&self.routes, routes, &self.applied_routes).await?;
        let (default_v4, default_v6) = self.routes.get_default_routes().await.map_err(|error| {
            AppError::Runtime(format!("cannot inspect physical default routes: {error}"))
        })?;
        let previous = self.applied_routes.clone();
        self.routes.clear_routes().map_err(|error| {
            AppError::Runtime(format!(
                "cannot clear the previous Talpid route plan: {error}"
            ))
        })?;
        verify::remove_route_clones(&self.routes, routes).await?;
        let required: HashSet<_> = routes.iter().map(required_route).collect();
        self.add_routes_with_retry(required)
            .await
            .map_err(|error| {
                AppError::Runtime(format!(
                    "cannot apply Talpid routes [{}]: {}",
                    route_plan_summary(routes),
                    format_error_chain(&error)
                ))
            })?;
        verify::verify_routes(
            &self.routes,
            routes,
            &previous,
            default_v4.as_ref().map(|route| route.interface_index),
            default_v6.as_ref().map(|route| route.interface_index),
        )
        .await?;
        self.applied_routes = routes.to_vec();
        Ok(())
    }

    async fn add_routes_with_retry(
        &self,
        required: HashSet<RequiredRoute>,
    ) -> std::result::Result<(), talpid_routing::Error> {
        const MAX_ATTEMPTS: usize = 3;

        for attempt in 1..=MAX_ATTEMPTS {
            match self.routes.add_routes(required.clone()).await {
                Ok(()) => return Ok(()),
                Err(error) if error.is_recoverable() && attempt < MAX_ATTEMPTS => {
                    self.routes.clear_routes()?;
                    // This read command is an acknowledgement fence for Talpid's
                    // fire-and-forget cleanup command.
                    let _ = self.routes.get_default_routes().await?;
                    sleep(Duration::from_millis(200 * attempt as u64)).await;
                }
                Err(error) => return Err(error),
            }
        }

        unreachable!("the bounded route retry loop always returns")
    }

    pub async fn prepare_routes(&self, routes: &[PlannedRoute]) -> Result<()> {
        verify::reject_route_conflicts(&self.routes, routes, &self.applied_routes).await
    }

    pub fn apply_firewall(&mut self, policy: &FirewallPlan) -> Result<()> {
        self.firewall.apply(policy)
    }

    pub fn prepare_firewall(&mut self) -> Result<()> {
        self.firewall.prepare()
    }

    pub fn cleanup_orphaned_firewall(&mut self) -> Result<()> {
        self.firewall.cleanup_orphans()
    }

    pub fn apply_dns(&mut self, plan: &AggregatePlan) -> Result<()> {
        match &plan.dns {
            Some(dns) => {
                if self.dns_baseline.is_none() {
                    self.dns_baseline = Some(dns_snapshot::capture()?);
                }
                let config = DnsConfig::from_addresses(&dns.servers, &[]).resolve(&[], 53);
                self.dns.set(&dns.interface, config).map_err(|error| {
                    AppError::Runtime(format!("cannot apply Talpid DNS configuration: {error}"))
                })?;
                dns_snapshot::apply_search_domains(&dns.search_domains)?;
                dns_snapshot::verify_config(&dns.servers, &dns.search_domains)
            }
            None => self.reset_dns(),
        }
    }

    fn reset_dns(&mut self) -> Result<()> {
        self.dns
            .reset()
            .map_err(|error| AppError::Runtime(format!("cannot reset Talpid DNS: {error}")))?;
        if let Some(snapshot) = &self.dns_baseline {
            dns_snapshot::restore(snapshot)?;
            dns_snapshot::verify_restored(snapshot)?;
            self.dns_baseline = None;
        }
        Ok(())
    }

    pub async fn recover_stale(&mut self, journal: &RecoveryJournal) -> Result<()> {
        if let Some(snapshot) = &journal.dns_snapshot {
            dns_snapshot::restore(snapshot)?;
            dns_snapshot::verify_restored(snapshot)?;
        }
        // Always inspect and remove project-owned PF artifacts. Older or
        // interrupted journals may not have persisted the anchor flag yet.
        let previous_pf_state = journal
            .pf_anchor_installed
            .then_some(journal.pf_was_enabled)
            .flatten();
        for route in &journal.routes {
            remove_stale_route(&self.routes, &route.prefix).await?;
        }
        self.routes.clear_routes().map_err(|error| {
            AppError::Runtime(format!("cannot restore physical default routes: {error}"))
        })?;
        // A read command sent after `clear_routes` is an acknowledgement fence for Talpid's
        // otherwise fire-and-forget cleanup command.
        let (default_v4, default_v6) = self.routes.get_default_routes().await.map_err(|error| {
            AppError::Runtime(format!("cannot await physical route restoration: {error}"))
        })?;
        verify::verify_routes_removed(
            &self.routes,
            &journal.routes,
            default_v4.as_ref().map(|route| route.interface_index),
            default_v6.as_ref().map(|route| route.interface_index),
        )
        .await?;
        // Keep crash protection until restoration has been verified.
        self.firewall.force_remove_anchor(previous_pf_state)?;
        self.applied_routes.clear();
        Ok(())
    }

    #[must_use]
    pub const fn pf_original_state(&self) -> Option<bool> {
        self.firewall.original_enabled_state()
    }

    pub async fn stop(mut self) -> Result<()> {
        let mut errors = Vec::new();
        let previous_routes = self.applied_routes.clone();
        if let Err(error) = self.reset_dns() {
            errors.push(error.to_string());
        }
        if let Err(error) = self.routes.clear_routes() {
            errors.push(format!("cannot clear routes while stopping: {error}"));
        }
        if let Err(error) = self.routes.get_default_routes().await {
            errors.push(format!(
                "cannot await route cleanup while stopping: {error}"
            ));
        }
        if let Err(error) =
            verify::verify_routes(&self.routes, &[], &previous_routes, None, None).await
        {
            errors.push(error.to_string());
        }
        if errors.is_empty()
            && let Err(error) = self.firewall.reset()
        {
            errors.push(error.to_string());
        }
        self.routes.stop().await;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(AppError::Runtime(errors.join("; ")))
        }
    }
}

fn required_route(route: &PlannedRoute) -> RequiredRoute {
    match &route.target {
        RouteTarget::PhysicalDefault => RequiredRoute::new(route.prefix, NetNode::DefaultNode),
        RouteTarget::Tunnel { interface, .. } => {
            RequiredRoute::new(route.prefix, Node::device(interface.clone()))
        }
    }
}

fn route_plan_summary(routes: &[PlannedRoute]) -> String {
    routes
        .iter()
        .map(|route| match &route.target {
            RouteTarget::PhysicalDefault => format!("{} -> physical", route.prefix),
            RouteTarget::Tunnel { interface, .. } => {
                format!("{} -> {interface}", route.prefix)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

async fn remove_stale_route(routes: &RouteManagerHandle, prefix: &str) -> Result<()> {
    let network: ipnetwork::IpNetwork = prefix
        .parse()
        .map_err(|error| AppError::Runtime(format!("invalid route in journal: {error}")))?;
    routes
        .remove_route(network)
        .await
        .map(|_| ())
        .map_err(|error| AppError::Runtime(format!("cannot remove stale route {prefix}: {error}")))
}
