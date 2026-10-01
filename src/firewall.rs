// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    cmp::Reverse,
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::planner::{ActiveProfile, AggregatePlan, RoutePurpose, RouteTarget, host_network};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NdpKind {
    RouterSolicitation,
    RouterAdvertisement,
    Redirect,
    NeighborSolicitation,
    NeighborAdvertisement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FirewallRule {
    AllowDns {
        interface: Option<String>,
        server: IpAddr,
        transport: Transport,
    },
    BlockClassicDns {
        transport: Transport,
    },
    AllowLoopback,
    AllowEndpoint {
        endpoint: SocketAddr,
    },
    AllowTunnel {
        interface: String,
    },
    AllowTunnelNetwork {
        interface: String,
        network: IpNetwork,
    },
    AllowDhcpV4,
    AllowDhcpV6,
    AllowNdp {
        message: NdpKind,
    },
    BlockNetwork {
        network: IpNetwork,
    },
    BlockAllOutbound,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FirewallPlan {
    pub rules: Vec<FirewallRule>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_owner: Option<String>,
    pub full_lockdown: bool,
    pub endpoint_exceptions: Vec<SocketAddr>,
    pub protected_destinations: Vec<IpNetwork>,
}

impl FirewallPlan {
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Endpoints whose states can only be created through the root-only pass.
    /// Outside split-tunnel coverage, unrelated host rules may admit ordinary
    /// application traffic, so those states cannot be trusted on a later switch
    /// to a full tunnel.
    pub fn restricted_endpoints(&self) -> Vec<SocketAddr> {
        self.endpoint_exceptions
            .iter()
            .copied()
            .filter(|endpoint| {
                self.full_lockdown
                    || self
                        .protected_destinations
                        .iter()
                        .any(|network| network.contains(endpoint.ip()))
            })
            .collect()
    }
}

#[must_use]
pub fn generate(active: &[ActiveProfile], routes: &AggregatePlan) -> FirewallPlan {
    generate_policy(active, routes, None)
}

/// Protect the requested destinations before its interface exists. Only already
/// active tunnels receive pass rules; the pending tunnel gets endpoint exceptions
/// and destination blocks. Full coverage locks down both address families.
#[must_use]
pub fn generate_connecting(
    active: &[ActiveProfile],
    routes: &AggregatePlan,
    pending: &crate::config::Profile,
    endpoints: &[SocketAddr],
) -> FirewallPlan {
    generate_policy(active, routes, Some((pending, endpoints)))
}

fn generate_policy(
    active: &[ActiveProfile],
    routes: &AggregatePlan,
    pending: Option<(&crate::config::Profile, &[SocketAddr])>,
) -> FirewallPlan {
    let mut protected_destinations: Vec<_> = active
        .iter()
        .flat_map(|profile| profile.allowed_routes.iter().copied())
        .collect();
    if let Some((profile, _)) = pending {
        protected_destinations.extend(profile.allowed_routes());
    }
    protected_destinations.sort_by_key(ToString::to_string);
    protected_destinations.dedup();
    let full_lockdown = [false, true]
        .into_iter()
        .any(|ipv6| crate::network::covers_family(protected_destinations.iter().copied(), ipv6));
    let mut tunnel_routes: Vec<_> = routes
        .routes
        .iter()
        .filter(|route| matches!(route.target, RouteTarget::Tunnel { .. }))
        .collect();
    // A narrower destination must be checked before a broader tunnel's pass.
    tunnel_routes.sort_by_key(|route| Reverse(route.prefix.prefix()));
    let routed_destinations: HashSet<_> = tunnel_routes.iter().map(|route| route.prefix).collect();
    let mut plan = FirewallPlan {
        full_lockdown,
        protected_destinations,
        ..FirewallPlan::default()
    };

    if let Some(dns) = &routes.dns {
        plan.dns_owner = Some(dns.owner.clone());
        plan.dns_servers.clone_from(&dns.servers);
        for server in &dns.servers {
            let interface = routes
                .routes
                .iter()
                .find(|route| {
                    route.purpose == RoutePurpose::DnsHost && route.prefix == host_network(*server)
                })
                .and_then(|route| match &route.target {
                    RouteTarget::Tunnel { interface, .. } => Some(interface.clone()),
                    RouteTarget::PhysicalDefault => None,
                });
            // A split profile can select DNS outside its allowed networks. If
            // any active profile requires full lockdown, never let that DNS
            // exception bypass the tunnel (including the other IP family).
            if interface.is_none()
                && (full_lockdown
                    || pending.is_some_and(|(profile, _)| {
                        profile
                            .allowed_routes()
                            .any(|network| network.contains(*server))
                    }))
            {
                continue;
            }
            plan.rules.push(FirewallRule::AllowDns {
                interface: interface.clone(),
                server: *server,
                transport: Transport::Tcp,
            });
            plan.rules.push(FirewallRule::AllowDns {
                interface,
                server: *server,
                transport: Transport::Udp,
            });
        }
    } else if let Some((profile, _)) = pending
        && profile.dns.is_some()
    {
        // No pending resolver may bypass protection before its tunnel exists.
        plan.dns_owner = Some(profile.name.clone());
    }
    if plan.dns_owner.is_some() {
        plan.rules.push(FirewallRule::BlockClassicDns {
            transport: Transport::Tcp,
        });
        plan.rules.push(FirewallRule::BlockClassicDns {
            transport: Transport::Udp,
        });
    }

    if full_lockdown || !plan.protected_destinations.is_empty() {
        plan.rules.push(FirewallRule::AllowLoopback);

        plan.endpoint_exceptions = active
            .iter()
            .flat_map(|profile| profile.endpoints.iter().copied())
            .collect();
        if let Some((_, endpoints)) = pending {
            plan.endpoint_exceptions.extend_from_slice(endpoints);
        }
        plan.endpoint_exceptions.sort_unstable();
        plan.endpoint_exceptions.dedup();
        for endpoint in &plan.endpoint_exceptions {
            plan.rules.push(FirewallRule::AllowEndpoint {
                endpoint: *endpoint,
            });
        }

        plan.rules.push(FirewallRule::AllowDhcpV4);
        plan.rules.push(FirewallRule::AllowDhcpV6);
        for message in [
            NdpKind::RouterSolicitation,
            NdpKind::RouterAdvertisement,
            NdpKind::Redirect,
            NdpKind::NeighborSolicitation,
            NdpKind::NeighborAdvertisement,
        ] {
            plan.rules.push(FirewallRule::AllowNdp { message });
        }

        // Preserve protection even when an endpoint host exception replaces an
        // allowed route. Only the endpoint's UDP port is exempt, not all traffic
        // to that address. Missing address families remain blocked as before.
        for network in &plan.protected_destinations {
            if routed_destinations.contains(network) {
                continue;
            }
            plan.rules
                .push(FirewallRule::BlockNetwork { network: *network });
        }

        if full_lockdown {
            let mut interfaces: Vec<_> = active
                .iter()
                .map(|profile| profile.interface.clone())
                .collect();
            interfaces.sort();
            interfaces.dedup();
            for interface in interfaces {
                plan.rules.push(FirewallRule::AllowTunnel { interface });
            }
            plan.rules.push(FirewallRule::BlockAllOutbound);
        } else {
            // Route replacement temporarily removes even unchanged split routes.
            // Permit their traffic only on the owning tunnel, then block fallback
            // to a physical default or another interface. Keep unrelated traffic
            // subject to the host's existing policy.
            for route in tunnel_routes {
                if let RouteTarget::Tunnel { interface, .. } = &route.target {
                    plan.rules.push(FirewallRule::AllowTunnelNetwork {
                        interface: interface.clone(),
                        network: route.prefix,
                    });
                    plan.rules.push(FirewallRule::BlockNetwork {
                        network: route.prefix,
                    });
                }
            }
        }
    }

    plan
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateView {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub transport: Transport,
}

#[must_use]
pub fn should_delete_state(
    policy: &FirewallPlan,
    state: StateView,
    previously_restricted_endpoints: &[SocketAddr],
) -> bool {
    if policy.dns_owner.is_some()
        && state.remote.port() == 53
        && matches!(state.transport, Transport::Tcp | Transport::Udp)
    {
        // Even a selected resolver's state can float onto a physical interface.
        // DNS passes are stateless so every packet must satisfy the current rule.
        return true;
    }

    if state.local.ip().is_loopback() || state.remote.ip().is_loopback() {
        return false;
    }
    if state.transport == Transport::Udp && policy.endpoint_exceptions.contains(&state.remote) {
        // PF does not expose the socket owner's UID in its state table. Old
        // states to a newly allowed endpoint must be evicted before we can rely
        // on the root-only pass rule; subsequent refreshes preserve transport.
        return !previously_restricted_endpoints.contains(&state.remote);
    }
    if policy
        .protected_destinations
        .iter()
        .any(|network| network.contains(state.remote.ip()))
    {
        return true;
    }
    // A tunnel source address does not prove that a PF state is bound to that
    // interface. Remove these states too; stateless tunnel rules recheck egress
    // after route changes, including loss of the tunnel.
    policy.full_lockdown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::{ActiveProfile, aggregate};

    fn full_profile() -> ActiveProfile {
        ActiveProfile {
            name: "work".to_owned(),
            priority: 100,
            dns_priority: 100,
            interface: "utun8".to_owned(),
            interface_addresses: vec!["10.0.0.2/32".parse().unwrap_or_else(|e| panic!("{e}"))],
            allowed_routes: vec!["0.0.0.0/0".parse().unwrap_or_else(|e| panic!("{e}"))],
            endpoints: vec![
                "203.0.113.1:51820"
                    .parse()
                    .unwrap_or_else(|e| panic!("{e}")),
            ],
            dns_servers: vec!["10.0.0.53".parse().unwrap_or_else(|e| panic!("{e}"))],
            dns_search_domains: Vec::new(),
        }
    }

    fn pending_profile(routes: &[&str]) -> crate::config::Profile {
        serde_json::from_value(serde_json::json!({
            "version": 1, "name": "pending", "priority": 200,
            "interface": { "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "addresses": ["10.1.0.2/32"] },
            "dns": { "servers": ["10.1.0.53"] },
            "peers": [{ "public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", "endpoint": "192.0.2.1:51820", "allowed_ips": routes }]
        })).unwrap()
    }

    #[test]
    fn connecting_full_policy_blocks_both_families_without_tunnel_passes() {
        for routes in [
            &["0.0.0.0/0"][..],
            &["::/0"][..],
            &["0.0.0.0/1", "128.0.0.0/1"][..],
        ] {
            let endpoint = "192.0.2.1:51820".parse().unwrap();
            let policy = generate_connecting(
                &[],
                &AggregatePlan::default(),
                &pending_profile(routes),
                &[endpoint],
            );
            assert!(policy.full_lockdown);
            assert_eq!(policy.endpoint_exceptions, [endpoint]);
            assert!(policy.rules.contains(&FirewallRule::BlockAllOutbound));
            assert!(policy.rules.contains(&FirewallRule::BlockClassicDns {
                transport: Transport::Udp
            }));
            assert!(policy.rules.iter().all(|rule| !matches!(
                rule,
                FirewallRule::AllowTunnel { .. }
                    | FirewallRule::AllowTunnelNetwork { .. }
                    | FirewallRule::AllowDns { .. }
            )));
            // Existing application/DNS/endpoint states are evicted before startup.
            for remote in ["192.0.2.1:51820", "198.51.100.1:443", "[2001:db8::1]:53"] {
                assert!(should_delete_state(
                    &policy,
                    StateView {
                        local: "192.0.2.2:12345".parse().unwrap(),
                        remote: remote.parse().unwrap(),
                        transport: Transport::Udp,
                    },
                    &[]
                ));
            }
        }
    }

    #[test]
    fn connecting_split_policy_covers_pending_destinations_without_widening_passes() {
        let mut active = full_profile();
        active.allowed_routes = vec!["10.0.0.0/24".parse().unwrap()];
        let active = [active];
        let policy = generate_connecting(
            &active,
            &aggregate(&active),
            &pending_profile(&["10.1.0.0/24", "2001:db8::/64"]),
            &[],
        );
        assert!(!policy.full_lockdown);
        for network in ["10.0.0.0/24", "10.1.0.0/24", "2001:db8::/64"] {
            assert!(
                policy
                    .protected_destinations
                    .contains(&network.parse().unwrap())
            );
            assert!(policy.rules.contains(&FirewallRule::BlockNetwork {
                network: network.parse().unwrap()
            }));
        }
        assert!(policy.rules.contains(&FirewallRule::AllowTunnelNetwork {
            interface: "utun8".into(),
            network: "10.0.0.0/24".parse().unwrap(),
        }));
        assert!(!policy.rules.contains(&FirewallRule::BlockAllOutbound));
    }

    #[test]
    fn connecting_union_can_require_full_lockdown_and_restrict_existing_external_dns() {
        let mut active = full_profile();
        active.allowed_routes = vec!["0.0.0.0/1".parse().unwrap()];
        active.dns_servers = vec!["198.51.100.53".parse().unwrap()];
        let active = [active];
        for pending_routes in [&["128.0.0.0/1"][..], &["198.51.100.0/24"][..]] {
            let policy = generate_connecting(
                &active,
                &aggregate(&active),
                &pending_profile(pending_routes),
                &[],
            );
            assert!(policy.rules.iter().all(|rule| !matches!(
                rule,
                FirewallRule::AllowDns {
                    interface: None,
                    ..
                }
            )));
            assert_eq!(policy.full_lockdown, pending_routes == ["128.0.0.0/1"]);
        }
    }

    #[test]
    fn generated_full_tunnel_policy_is_fail_closed_and_blocks_dns_leaks() {
        let active = vec![full_profile()];
        let routes = aggregate(&active);
        let policy = generate(&active, &routes);
        assert!(policy.full_lockdown);
        assert!(policy.rules.contains(&FirewallRule::AllowDns {
            interface: Some("utun8".to_owned()),
            server: "10.0.0.53".parse().unwrap_or_else(|e| panic!("{e}")),
            transport: Transport::Udp,
        }));
        assert!(policy.rules.contains(&FirewallRule::BlockClassicDns {
            transport: Transport::Udp,
        }));
        assert_eq!(policy.rules.last(), Some(&FirewallRule::BlockAllOutbound));
        assert!(!policy.rules.iter().any(
            |rule| matches!(rule, FirewallRule::AllowTunnel { interface } if interface == "en0")
        ));
    }

    #[test]
    fn subdivided_defaults_enable_lockdown_even_across_profiles() {
        for prefixes in [["0.0.0.0/1", "128.0.0.0/1"], ["::/1", "8000::/1"]] {
            let mut first = full_profile();
            first.allowed_routes = prefixes
                .iter()
                .map(|prefix| prefix.parse().unwrap())
                .collect();
            let active = vec![first.clone()];
            assert!(generate(&active, &aggregate(&active)).full_lockdown);

            let mut second = first.clone();
            second.name = "second".into();
            second.allowed_routes = vec![first.allowed_routes.pop().unwrap()];
            let active = vec![first, second];
            let policy = generate(&active, &aggregate(&active));
            assert!(policy.full_lockdown);
            assert_eq!(policy.rules.last(), Some(&FirewallRule::BlockAllOutbound));
        }
    }

    #[test]
    fn split_dns_policy_does_not_block_non_dns_traffic() {
        let mut profile = full_profile();
        profile.allowed_routes = vec!["10.0.0.0/8".parse().unwrap_or_else(|e| panic!("{e}"))];
        let active = vec![profile];
        let routes = aggregate(&active);
        let policy = generate(&active, &routes);
        assert!(!policy.full_lockdown);
        assert!(!policy.rules.contains(&FirewallRule::BlockAllOutbound));
        assert!(
            policy
                .rules
                .iter()
                .any(|rule| matches!(rule, FirewallRule::BlockClassicDns { .. }))
        );
    }

    #[test]
    fn split_tunnel_without_dns_blocks_physical_fallback_and_floating_states() {
        let mut profile = full_profile();
        let network: IpNetwork = "10.0.0.0/8".parse().unwrap();
        profile.allowed_routes = vec![network];
        profile.dns_servers.clear();
        let active = vec![profile];
        let policy = generate(&active, &aggregate(&active));
        assert!(policy.is_active());
        assert!(!policy.full_lockdown);
        assert!(
            policy
                .rules
                .contains(&FirewallRule::BlockNetwork { network })
        );
        assert!(!policy.rules.contains(&FirewallRule::BlockAllOutbound));
        for local in ["192.0.2.2:40000", "10.0.0.2:40000"] {
            let state = StateView {
                local: local.parse().unwrap(),
                remote: "10.20.30.40:443".parse().unwrap(),
                transport: Transport::Tcp,
            };
            assert!(should_delete_state(
                &policy,
                state,
                &policy.endpoint_exceptions
            ));
            assert!(!should_delete_state(
                &policy,
                StateView {
                    remote: "198.51.100.10:443".parse().unwrap(),
                    ..state
                },
                &policy.endpoint_exceptions
            ));
        }
    }

    #[test]
    fn split_rules_enforce_the_longest_prefix_owner_in_both_families() {
        for (broad, narrow) in [("10.0.0.0/8", "10.20.0.0/16"), ("fd00::/8", "fd00:1::/32")] {
            let broad = broad.parse().unwrap();
            let narrow = narrow.parse().unwrap();
            let mut first = full_profile();
            first
                .interface_addresses
                .push("fd00::2/128".parse().unwrap());
            first.allowed_routes = vec![broad];
            first.dns_servers.clear();
            let mut second = first.clone();
            second.name = "second".into();
            second.interface = "utun9".into();
            second.allowed_routes = vec![narrow];
            let active = vec![first, second];
            let policy = generate(&active, &aggregate(&active));
            let position =
                |rule: FirewallRule| policy.rules.iter().position(|r| *r == rule).unwrap();
            let narrow_pass = position(FirewallRule::AllowTunnelNetwork {
                interface: "utun9".into(),
                network: narrow,
            });
            let narrow_block = position(FirewallRule::BlockNetwork { network: narrow });
            let broad_pass = position(FirewallRule::AllowTunnelNetwork {
                interface: "utun8".into(),
                network: broad,
            });
            let broad_block = position(FirewallRule::BlockNetwork { network: broad });
            // A packet for the narrow subnet on utun8 must hit its block
            // before the broad subnet's pass can let it through.
            assert!(
                narrow_pass < narrow_block && narrow_block < broad_pass && broad_pass < broad_block
            );
            let endpoint = position(FirewallRule::AllowEndpoint {
                endpoint: active[0].endpoints[0],
            });
            assert!(endpoint < narrow_pass);
        }
    }

    #[test]
    fn host_route_overrides_do_not_remove_split_destination_protection() {
        for (address, dns) in [("10.0.0.53", true), ("203.0.113.1", false)] {
            let mut profile = full_profile();
            let network = host_network(address.parse().unwrap());
            profile.allowed_routes = vec![network];
            if !dns {
                profile.dns_servers.clear();
            }
            let active = vec![profile];
            let routes = aggregate(&active);
            assert!(
                !routes
                    .routes
                    .iter()
                    .any(|route| route.purpose == RoutePurpose::AllowedIp)
            );
            let policy = generate(&active, &routes);
            assert!(
                policy
                    .rules
                    .contains(&FirewallRule::BlockNetwork { network })
            );
            assert!(should_delete_state(
                &policy,
                StateView {
                    local: "192.0.2.2:40000".parse().unwrap(),
                    remote: SocketAddr::new(address.parse().unwrap(), 443),
                    transport: Transport::Tcp,
                },
                &policy.endpoint_exceptions
            ));
            if dns {
                assert!(policy.rules.contains(&FirewallRule::AllowTunnelNetwork {
                    interface: "utun8".into(),
                    network,
                }));
            }
        }
    }

    #[test]
    fn dns_firewall_interface_follows_the_aggregate_route() {
        let mut site = full_profile();
        site.name = "site".to_owned();
        site.interface = "utun8".to_owned();
        site.allowed_routes = vec!["192.0.2.0/24".parse().unwrap()];
        site.dns_servers = vec!["203.0.113.53".parse().unwrap()];

        let mut internet = full_profile();
        internet.name = "internet".to_owned();
        internet.priority = 0;
        internet.dns_priority = 0;
        internet.interface = "utun9".to_owned();

        let active = vec![site.clone(), internet];
        let policy = generate(&active, &aggregate(&active));
        assert!(policy.rules.contains(&FirewallRule::AllowDns {
            interface: Some("utun9".to_owned()),
            server: "203.0.113.53".parse().unwrap(),
            transport: Transport::Udp,
        }));

        let active = vec![site];
        let policy = generate(&active, &aggregate(&active));
        assert!(policy.rules.contains(&FirewallRule::AllowDns {
            interface: None,
            server: "203.0.113.53".parse().unwrap(),
            transport: Transport::Udp,
        }));
    }

    #[test]
    fn ipv6_allowed_ip_without_ipv6_address_is_blocked_before_tunnel_allow() {
        let mut profile = full_profile();
        let ipv6_default: IpNetwork = "::/0".parse().unwrap_or_else(|error| panic!("{error}"));
        profile.allowed_routes.push(ipv6_default);
        let active = vec![profile];
        let routes = aggregate(&active);
        let policy = generate(&active, &routes);

        let block_position = policy
            .rules
            .iter()
            .position(|rule| {
                matches!(rule, FirewallRule::BlockNetwork { network } if *network == ipv6_default)
            })
            .unwrap_or_else(|| panic!("missing IPv6 block rule"));
        let tunnel_position = policy
            .rules
            .iter()
            .position(|rule| matches!(rule, FirewallRule::AllowTunnel { .. }))
            .unwrap_or_else(|| panic!("missing tunnel allow rule"));
        assert!(block_position < tunnel_position);
        assert!(
            !routes
                .routes
                .iter()
                .any(|route| route.prefix == ipv6_default)
        );

        let ipv6_state = StateView {
            local: "[2001:db8::10]:40000"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            remote: "[2001:4860:4860::8888]:443"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            transport: Transport::Tcp,
        };
        assert!(should_delete_state(
            &policy,
            ipv6_state,
            &policy.endpoint_exceptions
        ));
    }

    #[test]
    fn state_cleanup_preserves_endpoints_but_removes_floating_tunnel_states() {
        let active = vec![full_profile()];
        let policy = generate(&active, &aggregate(&active));
        let endpoint = StateView {
            local: "192.168.1.10:40000"
                .parse()
                .unwrap_or_else(|e| panic!("{e}")),
            remote: "203.0.113.1:51820"
                .parse()
                .unwrap_or_else(|e| panic!("{e}")),
            transport: Transport::Udp,
        };
        assert!(!should_delete_state(
            &policy,
            endpoint,
            &policy.endpoint_exceptions
        ));
        // A state created before installing the root-only exception has no
        // trustworthy owner information. Force it through the new UID check.
        assert!(should_delete_state(&policy, endpoint, &[]));
        assert!(should_delete_state(
            &policy,
            endpoint,
            &["203.0.113.2:51820".parse().unwrap()],
        ));
        let tunnel = StateView {
            local: "10.0.0.2:40000".parse().unwrap_or_else(|e| panic!("{e}")),
            remote: "198.51.100.10:443"
                .parse()
                .unwrap_or_else(|e| panic!("{e}")),
            transport: Transport::Tcp,
        };
        assert!(should_delete_state(
            &policy,
            tunnel,
            &policy.endpoint_exceptions
        ));
        let physical = StateView {
            local: "192.168.1.10:40000"
                .parse()
                .unwrap_or_else(|e| panic!("{e}")),
            remote: "198.51.100.10:443"
                .parse()
                .unwrap_or_else(|e| panic!("{e}")),
            transport: Transport::Tcp,
        };
        assert!(should_delete_state(
            &policy,
            physical,
            &policy.endpoint_exceptions
        ));
    }

    #[test]
    fn full_lockdown_never_allows_dns_without_a_tunnel_route() {
        for (default, dns, address, subnet) in [
            (
                "0.0.0.0/0",
                "2001:db8::53",
                "2001:db8:1::2/128",
                "2001:db8:1::/64",
            ),
            ("::/0", "192.0.2.53", "192.0.2.2/32", "192.0.2.128/25"),
        ] {
            let mut full = full_profile();
            full.allowed_routes = vec![default.parse().unwrap()];
            full.interface_addresses
                .push("fd00::2/128".parse().unwrap());
            let mut site = full_profile();
            site.name = "site".into();
            site.interface = "utun9".into();
            site.dns_priority = 200;
            site.interface_addresses = vec![address.parse().unwrap()];
            site.allowed_routes = vec![subnet.parse().unwrap()];
            site.dns_servers = vec![dns.parse().unwrap()];
            let active = vec![full, site];
            let policy = generate(&active, &aggregate(&active));
            assert!(policy.full_lockdown);
            assert_eq!(policy.dns_owner.as_deref(), Some("site"));
            assert!(!policy.rules.iter().any(|rule| matches!(
                rule,
                FirewallRule::AllowDns {
                    interface: None,
                    ..
                }
            )));
            for transport in [Transport::Tcp, Transport::Udp] {
                assert!(
                    policy
                        .rules
                        .contains(&FirewallRule::BlockClassicDns { transport })
                );
            }
        }
    }

    #[test]
    fn moving_from_split_to_full_evicts_previously_unrestricted_endpoint_states() {
        for (endpoint, local, split_network) in [
            ("203.0.113.1:51820", "192.0.2.2:40000", "10.0.0.0/8"),
            ("[2001:db8::1]:51820", "[2001:db8::2]:40000", "fd00::/8"),
        ] {
            let mut profile = full_profile();
            profile.endpoints = vec![endpoint.parse().unwrap()];
            profile.allowed_routes = vec![split_network.parse().unwrap()];
            profile.dns_servers.clear();
            profile
                .interface_addresses
                .push("fd00::2/128".parse().unwrap());
            let active = vec![profile.clone()];
            let split = generate(&active, &aggregate(&active));
            assert!(split.restricted_endpoints().is_empty());

            profile.allowed_routes = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
            let active = vec![profile];
            let full = generate(&active, &aggregate(&active));
            let state = StateView {
                local: local.parse().unwrap(),
                remote: endpoint.parse().unwrap(),
                transport: Transport::Udp,
            };
            assert!(should_delete_state(
                &full,
                state,
                &split.restricted_endpoints()
            ));
            assert!(!should_delete_state(
                &full,
                state,
                &full.restricted_endpoints()
            ));
        }
    }

    #[test]
    fn state_cleanup_removes_dns_states_without_disrupting_unrelated_split_traffic() {
        let mut profile = full_profile();
        profile.allowed_routes = vec!["10.0.0.0/8".parse().unwrap_or_else(|e| panic!("{e}"))];
        let active = vec![profile];
        let policy = generate(&active, &aggregate(&active));
        let leaked_dns = StateView {
            local: "192.168.1.10:40000"
                .parse()
                .unwrap_or_else(|e| panic!("{e}")),
            remote: "8.8.8.8:53".parse().unwrap_or_else(|e| panic!("{e}")),
            transport: Transport::Udp,
        };
        assert!(should_delete_state(
            &policy,
            leaked_dns,
            &policy.endpoint_exceptions
        ));
        let selected_but_physical = StateView {
            local: "192.168.1.10:40000"
                .parse()
                .unwrap_or_else(|e| panic!("{e}")),
            remote: "10.0.0.53:53".parse().unwrap_or_else(|e| panic!("{e}")),
            transport: Transport::Udp,
        };
        assert!(should_delete_state(
            &policy,
            selected_but_physical,
            &policy.endpoint_exceptions
        ));
        let selected_in_tunnel = StateView {
            local: "10.0.0.2:40000".parse().unwrap_or_else(|e| panic!("{e}")),
            remote: "10.0.0.53:53".parse().unwrap_or_else(|e| panic!("{e}")),
            transport: Transport::Udp,
        };
        assert!(should_delete_state(
            &policy,
            selected_in_tunnel,
            &policy.endpoint_exceptions
        ));
        let unrelated = StateView {
            local: "192.168.1.10:40000"
                .parse()
                .unwrap_or_else(|e| panic!("{e}")),
            remote: "198.51.100.10:443"
                .parse()
                .unwrap_or_else(|e| panic!("{e}")),
            transport: Transport::Tcp,
        };
        assert!(!should_delete_state(
            &policy,
            unrelated,
            &policy.endpoint_exceptions
        ));
    }
}
