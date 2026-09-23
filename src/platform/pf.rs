// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    process::Command,
};

use ipnetwork::{IpNetwork, Ipv6Network};
use pfctl::{DropAction, FilterRule, FilterRuleAction, FilterRuleBuilder, StatePolicy};

use crate::{
    AppError, Result,
    firewall::{FirewallPlan, FirewallRule, NdpKind, StateView, Transport, should_delete_state},
};

const FILTER_ANCHOR: &str = "simplevpn";
const SCRUB_ANCHOR: &str = "simplevpn-scrub";
const MAX_CLEANUP_PASSES: usize = 64;

pub struct PfController {
    pf: pfctl::PfCtl,
    was_enabled: Option<bool>,
    active: bool,
}

impl PfController {
    pub fn new() -> Result<Self> {
        let pf = pfctl::PfCtl::new()
            .map_err(|error| AppError::Platform(format!("cannot open /dev/pf: {error}")))?;
        Ok(Self {
            pf,
            was_enabled: None,
            active: false,
        })
    }

    pub fn apply(&mut self, policy: &FirewallPlan) -> Result<()> {
        if !policy.is_active() {
            if !self.active {
                self.was_enabled = None;
                return Ok(());
            }
            return self.reset();
        }
        self.prepare()?;
        self.pf.try_enable().map_err(pf_error)?;
        // From this point onward rollback must remove our state even if a later write fails.
        self.active = true;
        self.pf
            .try_add_anchor(FILTER_ANCHOR, pfctl::AnchorKind::Filter)
            .and_then(|()| {
                self.pf
                    .try_add_anchor(SCRUB_ANCHOR, pfctl::AnchorKind::Scrub)
            })
            .map_err(pf_error)?;

        let mut rules = Vec::new();
        for rule in &policy.rules {
            rules.extend(build_rule(rule)?);
        }
        let expected_filter_rules = rules.len();
        let scrub = pfctl::ScrubRuleBuilder::default()
            .action(pfctl::ScrubRuleAction::Scrub)
            .build()
            .map_err(pf_error)?;
        let mut filter_change = pfctl::AnchorChange::new();
        filter_change.set_filter_rules(rules);
        let mut scrub_change = pfctl::AnchorChange::new();
        scrub_change.set_scrub_rules(vec![scrub]);
        let mut transaction = pfctl::Transaction::new();
        transaction.add_change(FILTER_ANCHOR, filter_change);
        transaction.add_change(SCRUB_ANCHOR, scrub_change);
        transaction.commit().map_err(pf_error)?;
        self.verify_active(expected_filter_rules)?;
        self.cleanup_states(policy)?;
        Ok(())
    }

    pub fn prepare(&mut self) -> Result<()> {
        if self.was_enabled.is_none() {
            self.was_enabled = Some(self.pf.is_enabled().map_err(pf_error)?);
        }
        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        if !self.active && self.was_enabled.is_none() {
            return Ok(());
        }
        let mut first_error = None;
        // Flush every ruleset kind because earlier failed versions could leave
        // duplicate or mixed-kind references under the shared legacy anchor.
        for anchor in [FILTER_ANCHOR, SCRUB_ANCHOR] {
            for kind in [
                pfctl::RulesetKind::Filter,
                pfctl::RulesetKind::Nat,
                pfctl::RulesetKind::Redirect,
                pfctl::RulesetKind::Scrub,
            ] {
                record_optional_anchor_cleanup(self.pf.flush_rules(anchor, kind), &mut first_error);
            }
        }
        if let Err(error) = clear_all_anchor_states(&mut self.pf) {
            first_error.get_or_insert(error);
        }
        for anchor in [FILTER_ANCHOR, SCRUB_ANCHOR] {
            for kind in [
                pfctl::AnchorKind::Filter,
                pfctl::AnchorKind::Nat,
                pfctl::AnchorKind::Redirect,
                pfctl::AnchorKind::Scrub,
            ] {
                if let Err(error) = remove_all_anchor_references(&mut self.pf, anchor, kind) {
                    first_error.get_or_insert(error);
                }
            }
        }
        let was_enabled = self.was_enabled;
        if let Some(was_enabled) = was_enabled {
            let result = if was_enabled {
                self.pf.try_enable()
            } else {
                self.pf.try_disable()
            };
            if let Err(error) = result {
                first_error.get_or_insert_with(|| pf_error(error));
            }
        }
        if let Err(error) = self.verify_reset(was_enabled) {
            first_error.get_or_insert(error);
        }
        match first_error {
            Some(error) => {
                // Retain ownership and the original PF state so the same
                // controller can retry cleanup without relying on a restart.
                self.active = true;
                Err(error)
            }
            None => {
                self.active = false;
                self.was_enabled = None;
                Ok(())
            }
        }
    }

    pub fn force_remove_anchor(&mut self, was_enabled: Option<bool>) -> Result<()> {
        self.was_enabled = was_enabled;
        self.active = true;
        self.reset()
    }

    pub fn cleanup_orphans(&mut self) -> Result<()> {
        if self.project_firewall_present()? {
            self.force_remove_anchor(None)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub const fn original_enabled_state(&self) -> Option<bool> {
        self.was_enabled
    }

    fn cleanup_states(&mut self, policy: &FirewallPlan) -> Result<()> {
        for _ in 0..MAX_CLEANUP_PASSES {
            let mut removed = 0_usize;
            for state in self.pf.get_states().map_err(pf_error)? {
                // `pfctl` sizes its state buffer using an earlier count. If states disappear
                // between the count and fetch ioctls, the crate exposes zero-filled trailing
                // slots with AF_UNSPEC. They are not kernel states and cannot be killed.
                let Some(view) = state_view(&state)? else {
                    continue;
                };
                if should_delete_state(policy, view) {
                    self.pf.kill_state(&state).map_err(pf_error)?;
                    removed += 1;
                }
            }
            if removed == 0 {
                return Ok(());
            }
        }
        Err(verification_error(format!(
            "disallowed PF states remain after {MAX_CLEANUP_PASSES} cleanup passes"
        )))
    }

    fn verify_active(&mut self, expected_filter_rules: usize) -> Result<()> {
        if !self.pf.is_enabled().map_err(pf_error)? {
            return Err(verification_error(
                "PF is disabled after applying firewall rules",
            ));
        }
        let output = Command::new("/sbin/pfctl")
            .args(["-a", FILTER_ANCHOR, "-sr"])
            .output()
            .map_err(|error| AppError::Platform(format!("cannot verify PF rules: {error}")))?;
        if !output.status.success() {
            return Err(verification_error(format!(
                "cannot read PF anchor rules: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let actual = rule_count(&String::from_utf8_lossy(&output.stdout));
        if actual != expected_filter_rules {
            return Err(verification_error(format!(
                "PF anchor contains {actual} filter rules, expected {expected_filter_rules}"
            )));
        }
        let output = Command::new("/sbin/pfctl")
            .args(["-a", SCRUB_ANCHOR, "-sr"])
            .output()
            .map_err(|error| AppError::Platform(format!("cannot verify PF scrub rule: {error}")))?;
        if !output.status.success() {
            return Err(verification_error(format!(
                "cannot read PF scrub anchor rules: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let scrub_rules = String::from_utf8_lossy(&output.stdout);
        if rule_count(&scrub_rules) != 1 || !scrub_rules.lines().any(|line| line.contains("scrub"))
        {
            return Err(verification_error(
                "PF scrub anchor does not contain exactly one scrub rule",
            ));
        }
        let root_filter = read_pfctl(&["-sr"], "cannot inspect root PF filter rules")?;
        for anchor in [FILTER_ANCHOR, SCRUB_ANCHOR] {
            let references = anchor_reference_count(&root_filter, anchor);
            if references != 1 {
                return Err(verification_error(format!(
                    "root PF rules contain {references} references to {anchor}, expected 1"
                )));
            }
        }
        let root_nat = read_pfctl(&["-sn"], "cannot inspect root PF NAT rules")?;
        if [FILTER_ANCHOR, SCRUB_ANCHOR]
            .iter()
            .any(|anchor| references_anchor(&root_nat, anchor))
        {
            return Err(verification_error(
                "root PF NAT rules unexpectedly reference a SimpleVPN anchor",
            ));
        }
        Ok(())
    }

    fn verify_reset(&mut self, expected_enabled: Option<bool>) -> Result<()> {
        if let Some(expected) = expected_enabled {
            let actual = self.pf.is_enabled().map_err(pf_error)?;
            if actual != expected {
                return Err(verification_error(format!(
                    "PF enabled state is {actual}, expected {expected}"
                )));
            }
        }
        if self.project_firewall_present()? {
            return Err(verification_error(
                "SimpleVPN PF rules or root anchor references remain after removal",
            ));
        }
        Ok(())
    }

    fn project_firewall_present(&self) -> Result<bool> {
        for anchor in [FILTER_ANCHOR, SCRUB_ANCHOR] {
            for show in ["-sr", "-sn"] {
                let rules = read_pfctl(&["-a", anchor, show], "cannot inspect PF anchor")?;
                if rule_count(&rules) != 0 {
                    return Ok(true);
                }
            }
        }
        for show in ["-sr", "-sn"] {
            let root_rules = read_pfctl(&[show], "cannot inspect root PF rules")?;
            if [FILTER_ANCHOR, SCRUB_ANCHOR]
                .iter()
                .any(|anchor| references_anchor(&root_rules, anchor))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn state_view(state: &pfctl::State) -> Result<Option<StateView>> {
    let local = match state.local_address() {
        Ok(address) => address,
        Err(error) if error.kind() == pfctl::ErrorKind::InvalidAddressFamily => return Ok(None),
        Err(error) => return Err(pf_error(error)),
    };
    let remote = match state.remote_address() {
        Ok(address) => address,
        Err(error) if error.kind() == pfctl::ErrorKind::InvalidAddressFamily => return Ok(None),
        Err(error) => return Err(pf_error(error)),
    };
    Ok(Some(StateView {
        local,
        remote,
        transport: match state.proto() {
            Ok(pfctl::Proto::Udp) => Transport::Udp,
            Ok(pfctl::Proto::Tcp) => Transport::Tcp,
            Ok(_) | Err(_) => Transport::Other,
        },
    }))
}

fn rule_count(output: &str) -> usize {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

fn references_anchor(output: &str, anchor: &str) -> bool {
    anchor_reference_count(output, anchor) != 0
}

fn anchor_reference_count(output: &str, anchor: &str) -> usize {
    let exact = format!("\"{anchor}\"");
    let descendants = format!("\"{anchor}/*\"");
    output
        .lines()
        .filter(|line| line.contains(&exact) || line.contains(&descendants))
        .count()
}

fn read_pfctl(arguments: &[&str], context: &str) -> Result<String> {
    let output = Command::new("/sbin/pfctl")
        .args(arguments)
        .output()
        .map_err(|error| AppError::Platform(format!("{context}: {error}")))?;
    if !output.status.success() {
        return Err(verification_error(format!(
            "{context}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn build_rule(rule: &FirewallRule) -> Result<Vec<FilterRule>> {
    match rule {
        FirewallRule::AllowDns {
            interface,
            server,
            transport,
        } => {
            let mut builder = pass_builder();
            builder.direction(pfctl::Direction::Out).quick(true);
            if let Some(interface) = interface {
                builder.interface(interface.as_str());
            }
            Ok(vec![
                builder
                    .proto(protocol(*transport))
                    .to(pfctl::Endpoint::new(*server, 53))
                    // Floating state would bypass the interface check after a
                    // route change. Re-evaluate every DNS packet instead.
                    .keep_state(StatePolicy::None)
                    .build()
                    .map_err(pf_error)?,
            ])
        }
        FirewallRule::BlockClassicDns { transport } => Ok(vec![
            drop_builder()
                .direction(pfctl::Direction::Out)
                .quick(true)
                .proto(protocol(*transport))
                .to(pfctl::Port::from(53))
                .keep_state(StatePolicy::None)
                .build()
                .map_err(pf_error)?,
        ]),
        FirewallRule::AllowLoopback => Ok(vec![
            pass_builder()
                .quick(true)
                .interface("lo0")
                .keep_state(StatePolicy::Keep)
                .build()
                .map_err(pf_error)?,
        ]),
        FirewallRule::AllowEndpoint { endpoint } => Ok(vec![
            pass_builder()
                .direction(pfctl::Direction::Out)
                .quick(true)
                .proto(pfctl::Proto::Udp)
                .to(*endpoint)
                .keep_state(StatePolicy::Keep)
                .build()
                .map_err(pf_error)?,
        ]),
        FirewallRule::AllowTunnel { interface } => Ok(vec![
            pass_builder()
                .quick(true)
                .interface(interface.as_str())
                // Never let plaintext tunnel flows create state that can be
                // reused on a physical interface when the tunnel disappears.
                .keep_state(StatePolicy::None)
                .build()
                .map_err(pf_error)?,
        ]),
        FirewallRule::AllowTunnelNetwork { interface, network } => Ok(vec![
            pass_builder()
                .direction(pfctl::Direction::Out)
                .quick(true)
                .interface(interface.as_str())
                .af(if network.is_ipv4() {
                    pfctl::AddrFamily::Ipv4
                } else {
                    pfctl::AddrFamily::Ipv6
                })
                .to(pfctl::Ip::from(*network))
                .keep_state(StatePolicy::None)
                .build()
                .map_err(pf_error)?,
        ]),
        FirewallRule::AllowDhcpV4 => dhcp_v4_rules(),
        FirewallRule::AllowDhcpV6 => dhcp_v6_rules(),
        FirewallRule::AllowNdp { message } => ndp_rules(*message),
        FirewallRule::BlockNetwork { network } => Ok(vec![
            drop_builder()
                .direction(pfctl::Direction::Out)
                .quick(true)
                .af(if network.is_ipv4() {
                    pfctl::AddrFamily::Ipv4
                } else {
                    pfctl::AddrFamily::Ipv6
                })
                .to(pfctl::Ip::from(*network))
                .keep_state(StatePolicy::None)
                .build()
                .map_err(pf_error)?,
        ]),
        FirewallRule::BlockAllOutbound => Ok(vec![
            drop_builder()
                .direction(pfctl::Direction::Out)
                .quick(true)
                .keep_state(StatePolicy::None)
                .build()
                .map_err(pf_error)?,
        ]),
    }
}

fn dhcp_v4_rules() -> Result<Vec<FilterRule>> {
    Ok(vec![
        pass_builder()
            .direction(pfctl::Direction::Out)
            .quick(true)
            .af(pfctl::AddrFamily::Ipv4)
            .proto(pfctl::Proto::Udp)
            .from(pfctl::Port::from(68))
            .to(pfctl::Endpoint::new(Ipv4Addr::BROADCAST, 67))
            .build()
            .map_err(pf_error)?,
        pass_builder()
            .direction(pfctl::Direction::In)
            .quick(true)
            .af(pfctl::AddrFamily::Ipv4)
            .proto(pfctl::Proto::Udp)
            .from(pfctl::Port::from(67))
            .to(pfctl::Port::from(68))
            .build()
            .map_err(pf_error)?,
    ])
}

fn dhcp_v6_rules() -> Result<Vec<FilterRule>> {
    let link_local: IpNetwork = Ipv6Network::new(
        "fe80::"
            .parse::<Ipv6Addr>()
            .map_err(|error| AppError::Runtime(error.to_string()))?,
        10,
    )
    .map(IpNetwork::V6)
    .map_err(|error| AppError::Runtime(error.to_string()))?;
    let mut rules = Vec::new();
    for server in ["ff02::1:2", "ff05::1:3"] {
        rules.push(
            pass_builder()
                .direction(pfctl::Direction::Out)
                .quick(true)
                .af(pfctl::AddrFamily::Ipv6)
                .proto(pfctl::Proto::Udp)
                .from(pfctl::Endpoint::new(pfctl::Ip::from(link_local), 546))
                .to(pfctl::Endpoint::new(
                    server
                        .parse::<Ipv6Addr>()
                        .map_err(|error| AppError::Runtime(error.to_string()))?,
                    547,
                ))
                .build()
                .map_err(pf_error)?,
        );
    }
    rules.push(
        pass_builder()
            .direction(pfctl::Direction::In)
            .quick(true)
            .af(pfctl::AddrFamily::Ipv6)
            .proto(pfctl::Proto::Udp)
            .from(pfctl::Endpoint::new(pfctl::Ip::from(link_local), 547))
            .to(pfctl::Endpoint::new(pfctl::Ip::from(link_local), 546))
            .build()
            .map_err(pf_error)?,
    );
    Ok(rules)
}

fn ndp_rules(message: NdpKind) -> Result<Vec<FilterRule>> {
    let mut builder = pass_builder();
    builder
        .quick(true)
        .af(pfctl::AddrFamily::Ipv6)
        .proto(pfctl::Proto::IcmpV6)
        .icmp_type(pfctl::IcmpType::Icmp6(match message {
            NdpKind::RouterSolicitation => pfctl::Icmp6Type::RouterSol,
            NdpKind::RouterAdvertisement => pfctl::Icmp6Type::RouterAdv,
            NdpKind::Redirect => pfctl::Icmp6Type::Redir,
            NdpKind::NeighborSolicitation => pfctl::Icmp6Type::NeighbrSol,
            NdpKind::NeighborAdvertisement => pfctl::Icmp6Type::NeighbrAdv,
        }));
    let link_local = IpNetwork::V6(
        Ipv6Network::new(
            "fe80::"
                .parse::<Ipv6Addr>()
                .map_err(|error| AppError::Runtime(error.to_string()))?,
            10,
        )
        .map_err(|error| AppError::Runtime(error.to_string()))?,
    );
    let rules = match message {
        NdpKind::RouterSolicitation => vec![
            builder
                .direction(pfctl::Direction::Out)
                .to("ff02::2"
                    .parse::<Ipv6Addr>()
                    .map_err(|error| AppError::Runtime(error.to_string()))?)
                .build()
                .map_err(pf_error)?,
        ],
        NdpKind::RouterAdvertisement | NdpKind::Redirect => vec![
            builder
                .direction(pfctl::Direction::In)
                .from(pfctl::Ip::from(link_local))
                .build()
                .map_err(pf_error)?,
        ],
        NdpKind::NeighborSolicitation => {
            let solicited = IpNetwork::V6(
                Ipv6Network::new(
                    "ff02::1:ff00:0"
                        .parse::<Ipv6Addr>()
                        .map_err(|error| AppError::Runtime(error.to_string()))?,
                    104,
                )
                .map_err(|error| AppError::Runtime(error.to_string()))?,
            );
            vec![
                builder
                    .clone()
                    .direction(pfctl::Direction::Out)
                    .to(pfctl::Ip::from(solicited))
                    .build()
                    .map_err(pf_error)?,
                builder
                    .clone()
                    .direction(pfctl::Direction::Out)
                    .to(pfctl::Ip::from(link_local))
                    .build()
                    .map_err(pf_error)?,
                builder
                    .direction(pfctl::Direction::In)
                    .from(pfctl::Ip::from(link_local))
                    .build()
                    .map_err(pf_error)?,
            ]
        }
        NdpKind::NeighborAdvertisement => vec![
            builder
                .clone()
                .direction(pfctl::Direction::Out)
                .to(pfctl::Ip::from(link_local))
                .build()
                .map_err(pf_error)?,
            builder
                .direction(pfctl::Direction::In)
                .build()
                .map_err(pf_error)?,
        ],
    };
    Ok(rules)
}

fn pass_builder() -> FilterRuleBuilder {
    let mut builder = FilterRuleBuilder::default();
    builder.action(FilterRuleAction::Pass);
    builder
}

fn drop_builder() -> FilterRuleBuilder {
    let mut builder = FilterRuleBuilder::default();
    builder.action(FilterRuleAction::Drop(DropAction::Return));
    builder
}

const fn protocol(transport: Transport) -> pfctl::Proto {
    match transport {
        Transport::Tcp => pfctl::Proto::Tcp,
        Transport::Udp => pfctl::Proto::Udp,
        Transport::Other => pfctl::Proto::Any,
    }
}

fn pf_error(error: pfctl::Error) -> AppError {
    AppError::Runtime(format!("PF operation failed: {error}"))
}

fn record_optional_anchor_cleanup<T>(result: pfctl::Result<T>, first_error: &mut Option<AppError>) {
    if let Err(error) = result
        && error.kind() != pfctl::ErrorKind::AnchorDoesNotExist
    {
        first_error.get_or_insert_with(|| pf_error(error));
    }
}

fn remove_all_anchor_references(
    pf: &mut pfctl::PfCtl,
    anchor: &str,
    kind: pfctl::AnchorKind,
) -> Result<()> {
    for _ in 0..MAX_CLEANUP_PASSES {
        match pf.remove_anchor(anchor, kind) {
            Ok(()) => {}
            Err(error) if error.kind() == pfctl::ErrorKind::AnchorDoesNotExist => return Ok(()),
            Err(error) => return Err(pf_error(error)),
        }
    }
    Err(verification_error(format!(
        "PF anchor {anchor} has more than {MAX_CLEANUP_PASSES} {kind:?} references"
    )))
}

fn clear_all_anchor_states(pf: &mut pfctl::PfCtl) -> Result<()> {
    for _ in 0..MAX_CLEANUP_PASSES {
        match pf.clear_states(FILTER_ANCHOR, pfctl::AnchorKind::Filter) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == pfctl::ErrorKind::AnchorDoesNotExist => return Ok(()),
            Err(error) => return Err(pf_error(error)),
        }
    }
    Err(verification_error(format!(
        "PF anchor states remain after {MAX_CLEANUP_PASSES} cleanup passes"
    )))
}

fn verification_error(message: impl Into<String>) -> AppError {
    AppError::Runtime(format!(
        "system write verification failed: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_count_ignores_blank_pfctl_lines() {
        assert_eq!(rule_count("pass all\n\nblock drop out all\n"), 2);
    }

    #[test]
    fn root_rule_reference_detection_is_exact() {
        let rules = r#"anchor "simplevpn" all
scrub-anchor "simplevpn-scrub" all
anchor "not-simplevpn" all
"#;
        assert!(references_anchor(rules, FILTER_ANCHOR));
        assert!(references_anchor(rules, SCRUB_ANCHOR));
        assert!(!references_anchor(rules, "simple"));
        assert_eq!(anchor_reference_count(rules, FILTER_ANCHOR), 1);
    }
}
