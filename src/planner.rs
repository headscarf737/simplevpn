// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};

use crate::{AppError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActiveProfile {
    pub name: String,
    pub priority: i32,
    pub dns_priority: i32,
    pub interface: String,
    pub interface_addresses: Vec<IpNetwork>,
    pub allowed_routes: Vec<IpNetwork>,
    pub endpoints: Vec<SocketAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_search_domains: Vec<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTarget {
    PhysicalDefault,
    Tunnel { profile: String, interface: String },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePurpose {
    AllowedIp,
    EndpointException,
    DnsHost,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct PlannedRoute {
    pub prefix: IpNetwork,
    pub target: RouteTarget,
    pub purpose: RoutePurpose,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShadowedRoute {
    pub profile: String,
    pub prefix: IpNetwork,
    pub owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsSelection {
    pub owner: String,
    pub interface: String,
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AggregatePlan {
    pub routes: Vec<PlannedRoute>,
    pub blocked_routes: Vec<IpNetwork>,
    pub shadowed_routes: Vec<ShadowedRoute>,
    pub dns: Option<DnsSelection>,
    pub shadowed_dns: Vec<String>,
    pub full_tunnel_v4: Option<String>,
    pub full_tunnel_v6: Option<String>,
}

pub fn validate_candidate(active: &[ActiveProfile], candidate: &ActiveProfile) -> Result<()> {
    if active.iter().any(|profile| profile.name == candidate.name) {
        return Err(AppError::Runtime(format!(
            "profile '{}' is already active",
            candidate.name
        )));
    }

    for profile in active {
        if profile.dns_priority == candidate.dns_priority
            && !profile.dns_servers.is_empty()
            && !candidate.dns_servers.is_empty()
        {
            return Err(conflict(format!(
                "profile '{}' has the same DNS priority as active profile '{}'",
                candidate.name, profile.name
            )));
        }
        if profile.priority == candidate.priority {
            let existing: HashSet<_> = profile.allowed_routes.iter().copied().collect();
            if let Some(route) = candidate
                .allowed_routes
                .iter()
                .find(|route| existing.contains(route))
            {
                return Err(conflict(format!(
                    "route {route} has equal priority in profiles '{}' and '{}'",
                    profile.name, candidate.name
                )));
            }
        }
    }

    let all_dns = active
        .iter()
        .flat_map(|profile| profile.dns_servers.iter())
        .chain(candidate.dns_servers.iter());
    let all_endpoint_ips: HashSet<_> = active
        .iter()
        .flat_map(|profile| profile.endpoints.iter().map(SocketAddr::ip))
        .chain(candidate.endpoints.iter().map(SocketAddr::ip))
        .collect();
    if let Some(address) = all_dns
        .into_iter()
        .find(|address| all_endpoint_ips.contains(address))
    {
        return Err(conflict(format!(
            "address {address} cannot be both a VPN endpoint and a VPN DNS server"
        )));
    }

    Ok(())
}

#[must_use]
pub fn aggregate(active: &[ActiveProfile]) -> AggregatePlan {
    let mut profiles: Vec<_> = active.iter().collect();
    profiles.sort_by_key(|profile| (Reverse(profile.priority), profile.name.as_str()));

    let mut owned: HashMap<IpNetwork, &ActiveProfile> = HashMap::new();
    let mut shadowed_routes = Vec::new();
    for profile in &profiles {
        for route in &profile.allowed_routes {
            if let Some(owner) = owned.get(route) {
                shadowed_routes.push(ShadowedRoute {
                    profile: profile.name.clone(),
                    prefix: *route,
                    owner: owner.name.clone(),
                });
            } else {
                owned.insert(*route, profile);
            }
        }
    }

    let dns_profile = profiles
        .iter()
        .copied()
        .filter(|profile| !profile.dns_servers.is_empty())
        .min_by_key(|profile| (Reverse(profile.dns_priority), profile.name.as_str()));
    let dns = dns_profile.map(|profile| DnsSelection {
        owner: profile.name.clone(),
        interface: profile.interface.clone(),
        servers: profile.dns_servers.clone(),
        search_domains: profile.dns_search_domains.clone(),
    });
    let shadowed_dns = profiles
        .iter()
        .copied()
        .filter(|profile| {
            !profile.dns_servers.is_empty()
                && dns_profile.is_some_and(|owner| owner.name != profile.name)
        })
        .map(|profile| profile.name.clone())
        .collect();

    let mut routes = HashMap::<IpNetwork, PlannedRoute>::new();
    let mut blocked_routes = Vec::new();
    for (prefix, profile) in &owned {
        let has_address_family = profile
            .interface_addresses
            .iter()
            .any(|address| address.is_ipv4() == prefix.is_ipv4());
        if !has_address_family {
            blocked_routes.push(*prefix);
            continue;
        }
        routes.insert(
            *prefix,
            PlannedRoute {
                prefix: *prefix,
                target: RouteTarget::Tunnel {
                    profile: profile.name.clone(),
                    interface: profile.interface.clone(),
                },
                purpose: RoutePurpose::AllowedIp,
            },
        );
    }

    for profile in &profiles {
        for endpoint in &profile.endpoints {
            let prefix = host_network(endpoint.ip());
            routes.insert(
                prefix,
                PlannedRoute {
                    prefix,
                    target: RouteTarget::PhysicalDefault,
                    purpose: RoutePurpose::EndpointException,
                },
            );
        }
    }

    if let Some(selection) = &dns {
        for server in &selection.servers {
            let prefix = host_network(*server);
            let target =
                longest_route_target(&routes, *server).unwrap_or(RouteTarget::PhysicalDefault);
            routes.insert(
                prefix,
                PlannedRoute {
                    prefix,
                    target,
                    purpose: RoutePurpose::DnsHost,
                },
            );
        }
    }

    let mut routes: Vec<_> = routes.into_values().collect();
    routes.sort_by(|left, right| {
        left.prefix
            .ip()
            .is_ipv6()
            .cmp(&right.prefix.ip().is_ipv6())
            .then_with(|| left.prefix.prefix().cmp(&right.prefix.prefix()))
            .then_with(|| {
                left.prefix
                    .ip()
                    .to_string()
                    .cmp(&right.prefix.ip().to_string())
            })
    });
    shadowed_routes.sort_by(|left, right| {
        left.profile
            .cmp(&right.profile)
            .then_with(|| left.prefix.to_string().cmp(&right.prefix.to_string()))
    });
    blocked_routes.sort_by_key(ToString::to_string);

    let full_tunnel_v4 = Ipv4Network::new(std::net::Ipv4Addr::UNSPECIFIED, 0)
        .ok()
        .and_then(|default| owned.get(&IpNetwork::V4(default)))
        .map(|profile| profile.name.clone());
    let full_tunnel_v6 = Ipv6Network::new(std::net::Ipv6Addr::UNSPECIFIED, 0)
        .ok()
        .and_then(|default| owned.get(&IpNetwork::V6(default)))
        .map(|profile| profile.name.clone());

    AggregatePlan {
        routes,
        blocked_routes,
        shadowed_routes,
        dns,
        shadowed_dns,
        full_tunnel_v4,
        full_tunnel_v6,
    }
}

#[must_use]
pub fn host_network(address: IpAddr) -> IpNetwork {
    match address {
        IpAddr::V4(address) => IpNetwork::V4(Ipv4Network::from(address)),
        IpAddr::V6(address) => IpNetwork::V6(Ipv6Network::from(address)),
    }
}

fn longest_route_target(
    routes: &HashMap<IpNetwork, PlannedRoute>,
    address: IpAddr,
) -> Option<RouteTarget> {
    routes
        .values()
        .filter(|route| route.purpose == RoutePurpose::AllowedIp && route.prefix.contains(address))
        .max_by_key(|route| route.prefix.prefix())
        .map(|route| route.target.clone())
}

fn conflict(message: impl Into<String>) -> AppError {
    AppError::Runtime(format!("priority conflict: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(
        name: &str,
        priority: i32,
        interface: &str,
        routes: &[&str],
        dns: &[&str],
        endpoint: &str,
    ) -> ActiveProfile {
        ActiveProfile {
            name: name.to_owned(),
            priority,
            dns_priority: priority,
            interface: interface.to_owned(),
            interface_addresses: vec!["10.0.0.2/32".parse().unwrap_or_else(|e| panic!("{e}"))],
            allowed_routes: routes
                .iter()
                .map(|route| route.parse().unwrap_or_else(|e| panic!("{e}")))
                .collect(),
            endpoints: vec![endpoint.parse().unwrap_or_else(|e| panic!("{e}"))],
            dns_servers: dns
                .iter()
                .map(|server| server.parse().unwrap_or_else(|e| panic!("{e}")))
                .collect(),
            dns_search_domains: Vec::new(),
        }
    }

    #[test]
    fn different_prefixes_coexist_and_identical_route_is_shadowed() {
        let high = profile(
            "high",
            200,
            "utun8",
            &["10.0.0.0/8", "192.0.2.0/24"],
            &[],
            "203.0.113.1:51820",
        );
        let low = profile(
            "low",
            100,
            "utun9",
            &["10.0.0.0/8", "10.23.0.0/16"],
            &[],
            "203.0.113.2:51820",
        );
        let plan = aggregate(&[low, high]);
        assert!(
            plan.routes
                .iter()
                .any(|route| route.prefix.to_string() == "10.23.0.0/16")
        );
        assert_eq!(plan.shadowed_routes.len(), 1);
        assert_eq!(plan.shadowed_routes[0].profile, "low");
        assert_eq!(plan.shadowed_routes[0].owner, "high");
    }

    #[test]
    fn defaults_are_arbitrated_separately_by_family() {
        let ipv4 = profile(
            "v4",
            200,
            "utun8",
            &["0.0.0.0/0"],
            &["10.0.0.53"],
            "203.0.113.1:51820",
        );
        let ipv6 = profile(
            "v6",
            100,
            "utun9",
            &["::/0"],
            &["2001:db8::53"],
            "[2001:db8:ffff::1]:51820",
        );
        let plan = aggregate(&[ipv6, ipv4]);
        assert_eq!(plan.full_tunnel_v4.as_deref(), Some("v4"));
        assert_eq!(plan.full_tunnel_v6.as_deref(), Some("v6"));
    }

    #[test]
    fn ipv6_route_without_ipv6_interface_address_is_planned_as_blocked() {
        let active = profile(
            "work",
            100,
            "utun8",
            &["0.0.0.0/0", "::/0"],
            &["10.0.0.53"],
            "203.0.113.1:51820",
        );
        let plan = aggregate(&[active]);
        let ipv6_default: IpNetwork = "::/0".parse().unwrap_or_else(|error| panic!("{error}"));
        assert!(plan.blocked_routes.contains(&ipv6_default));
        assert!(!plan.routes.iter().any(|route| route.prefix == ipv6_default));
        assert_eq!(plan.full_tunnel_v6.as_deref(), Some("work"));
    }

    #[test]
    fn dns_and_endpoint_host_routes_have_explicit_targets() {
        let mut active = profile(
            "work",
            100,
            "utun8",
            &["0.0.0.0/0"],
            &["10.0.0.53"],
            "203.0.113.1:51820",
        );
        active.dns_search_domains = vec!["corp.example.com".to_owned()];
        let plan = aggregate(&[active]);
        assert_eq!(
            plan.dns.as_ref().map(|dns| dns
                .search_domains
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()),
            Some(vec!["corp.example.com"])
        );
        let endpoint = plan
            .routes
            .iter()
            .find(|route| route.prefix.to_string() == "203.0.113.1/32")
            .unwrap_or_else(|| panic!("missing endpoint route"));
        assert_eq!(endpoint.target, RouteTarget::PhysicalDefault);
        let dns = plan
            .routes
            .iter()
            .find(|route| route.prefix.to_string() == "10.0.0.53/32")
            .unwrap_or_else(|| panic!("missing DNS route"));
        assert_eq!(dns.purpose, RoutePurpose::DnsHost);
        assert!(matches!(
            &dns.target,
            RouteTarget::Tunnel { profile, interface }
                if profile == "work" && interface == "utun8"
        ));
    }

    #[test]
    fn dns_uses_the_aggregate_longest_prefix_route() {
        let site = profile(
            "site",
            100,
            "utun8",
            &["192.0.2.0/24"],
            &["203.0.113.53"],
            "203.0.113.1:51820",
        );
        let internet = profile(
            "internet",
            0,
            "utun9",
            &["0.0.0.0/0"],
            &["198.51.100.53"],
            "198.51.100.1:51820",
        );

        let plan = aggregate(&[site.clone(), internet]);
        assert_eq!(
            plan.dns.as_ref().map(|dns| dns.owner.as_str()),
            Some("site")
        );
        let dns_route = plan
            .routes
            .iter()
            .find(|route| route.prefix == host_network("203.0.113.53".parse().unwrap()))
            .unwrap();
        assert!(matches!(
            &dns_route.target,
            RouteTarget::Tunnel { profile, interface }
                if profile == "internet" && interface == "utun9"
        ));

        let plan = aggregate(&[site]);
        let dns_route = plan
            .routes
            .iter()
            .find(|route| route.prefix == host_network("203.0.113.53".parse().unwrap()))
            .unwrap();
        assert_eq!(dns_route.target, RouteTarget::PhysicalDefault);
    }

    #[test]
    fn lower_dns_takes_over_when_winner_stops() {
        let high = profile(
            "high",
            200,
            "utun8",
            &["10.0.0.0/8"],
            &["10.0.0.53"],
            "203.0.113.1:51820",
        );
        let low = profile(
            "low",
            100,
            "utun9",
            &["172.16.0.0/12"],
            &["172.16.0.53"],
            "203.0.113.2:51820",
        );
        let both = aggregate(&[low.clone(), high]);
        assert_eq!(
            both.dns.as_ref().map(|dns| dns.owner.as_str()),
            Some("high")
        );
        assert_eq!(both.shadowed_dns, vec!["low"]);
        let promoted = aggregate(&[low]);
        assert_eq!(
            promoted.dns.as_ref().map(|dns| dns.owner.as_str()),
            Some("low")
        );
    }

    #[test]
    fn equal_priority_conflicts_are_rejected() {
        let first = profile(
            "one",
            100,
            "utun8",
            &["10.0.0.0/8"],
            &["10.0.0.53"],
            "203.0.113.1:51820",
        );
        let second = profile(
            "two",
            100,
            "utun9",
            &["10.0.0.0/8"],
            &["10.0.0.54"],
            "203.0.113.2:51820",
        );
        let error = validate_candidate(&[first], &second).expect_err("conflict should be rejected");
        assert!(error.to_string().contains("priority conflict"));
    }

    #[test]
    fn longest_prefix_routes_coexist_and_standby_default_is_promoted() {
        let high = profile(
            "high",
            200,
            "utun8",
            &["0.0.0.0/0"],
            &["10.0.0.53"],
            "203.0.113.1:51820",
        );
        let mut low = profile(
            "low",
            100,
            "utun9",
            &["0.0.0.0/0", "192.0.2.0/24"],
            &["172.16.0.53"],
            "203.0.113.2:51820",
        );
        low.interface_addresses = vec![
            "172.16.0.2/32"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        ];
        let both = aggregate(&[low.clone(), high]);
        assert_eq!(both.full_tunnel_v4.as_deref(), Some("high"));
        assert!(
            both.routes
                .iter()
                .any(|route| route.prefix.to_string() == "192.0.2.0/24")
        );
        let promoted = aggregate(&[low]);
        assert_eq!(promoted.full_tunnel_v4.as_deref(), Some("low"));
    }
}
