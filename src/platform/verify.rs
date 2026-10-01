// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnetwork::IpNetwork;
use system_configuration::network_configuration::{SCNetworkInterfaceType, get_interfaces};
use talpid_routing::{RouteInfo, RouteManagerHandle};
use tokio::time::{Duration, sleep};

use crate::{
    AppError, Result,
    planner::{PlannedRoute, RouteTarget},
};

#[derive(Debug, Eq, PartialEq)]
struct InterfaceState {
    up: bool,
    mtu: u16,
    addresses: HashSet<IpNetwork>,
}

pub async fn verify_interface(
    interface: &str,
    expected_addresses: &[IpNetwork],
    expected_mtu: Option<u16>,
) -> Result<()> {
    let output = super::command::ifconfig(&[interface.to_owned()]).await?;
    if !output.status.success() {
        return Err(AppError::Platform(format!(
            "cannot verify interface {interface}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let state = parse_interface(&String::from_utf8_lossy(&output.stdout))?;
    if !state.up {
        return Err(verification_error(format!(
            "interface {interface} is not up after configuration"
        )));
    }
    if let Some(mtu) = expected_mtu
        && state.mtu != mtu
    {
        return Err(verification_error(format!(
            "interface {interface} has MTU {}, expected {mtu}",
            state.mtu
        )));
    }
    for address in expected_addresses {
        if !state.addresses.contains(address) {
            return Err(verification_error(format!(
                "interface {interface} is missing address {address}"
            )));
        }
    }
    Ok(())
}

pub async fn verify_interface_removed(interface: &str) -> Result<()> {
    for _ in 0..20 {
        let output = super::command::ifconfig(&[interface.to_owned()]).await?;
        if !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("does not exist")
        {
            return Ok(());
        }
        sleep(Duration::from_millis(50)).await;
    }
    Err(verification_error(format!(
        "interface {interface} still exists after tunnel shutdown"
    )))
}

pub async fn reject_route_conflicts(
    manager: &RouteManagerHandle,
    desired: &[PlannedRoute],
    previous: &[PlannedRoute],
) -> Result<()> {
    let previous: HashSet<_> = previous.iter().map(|route| route.prefix).collect();
    for route in desired {
        if route.prefix.prefix() == 0 || previous.contains(&route.prefix) {
            continue;
        }
        if let Some(existing) = inspect_route(manager, route.prefix).await?
            && route_conflicts(&existing, route)
        {
            return Err(verification_error(format!(
                "refusing to replace pre-existing route {} on interface {}",
                route.prefix,
                interface_label(existing.interface_index)
            )));
        }
    }
    Ok(())
}

pub async fn verify_routes(
    manager: &RouteManagerHandle,
    desired: &[PlannedRoute],
    previous: &[PlannedRoute],
    physical_v4: Option<u16>,
    physical_v6: Option<u16>,
) -> Result<()> {
    let physical_interfaces = if desired
        .iter()
        .any(|route| matches!(route.target, RouteTarget::PhysicalDefault))
    {
        physical_interface_indices()
    } else {
        HashSet::new()
    };
    for route in desired {
        let expected_interface = match &route.target {
            RouteTarget::Tunnel { interface, .. } => Some(interface_index(interface)?),
            RouteTarget::PhysicalDefault => {
                if route.prefix.is_ipv4() {
                    physical_v4
                } else {
                    physical_v6
                }
            }
        };
        let actual = inspect_route(manager, route.prefix).await?.ok_or_else(|| {
            verification_error(format!("route {} was not installed", route.prefix))
        })?;
        if !route_matches(&actual, route, expected_interface, &physical_interfaces) {
            let expected_interface = match &route.target {
                RouteTarget::Tunnel { interface, .. } => interface.clone(),
                RouteTarget::PhysicalDefault => "a physical network interface".to_owned(),
            };
            return Err(verification_error(format!(
                "route {} resolved as {} on {}, expected {} on {expected_interface}",
                route.prefix,
                actual.prefix,
                interface_label(actual.interface_index),
                route.prefix
            )));
        }
    }

    let desired_prefixes: HashSet<_> = desired.iter().map(|route| route.prefix).collect();
    for old in previous {
        if desired_prefixes.contains(&old.prefix) {
            continue;
        }
        let Some(actual) = inspect_route(manager, old.prefix).await? else {
            continue;
        };
        if actual.prefix != old.prefix {
            continue;
        }
        let still_uses_old_target = match &old.target {
            RouteTarget::Tunnel { interface, .. } => {
                actual.interface_index == interface_index(interface)?
            }
            RouteTarget::PhysicalDefault => !actual.was_cloned,
        };
        if still_uses_old_target {
            return Err(verification_error(format!(
                "stale route {} remains on interface {}",
                old.prefix,
                interface_label(actual.interface_index)
            )));
        }
    }
    Ok(())
}

fn physical_interface_indices() -> HashSet<u16> {
    get_interfaces()
        .iter()
        .filter(|interface| {
            matches!(
                interface.interface_type(),
                Some(
                    SCNetworkInterfaceType::Ethernet
                        | SCNetworkInterfaceType::IEEE80211
                        | SCNetworkInterfaceType::FireWire
                        | SCNetworkInterfaceType::WWAN
                        | SCNetworkInterfaceType::Bond
                        | SCNetworkInterfaceType::Bridge
                        | SCNetworkInterfaceType::VLAN
                )
            )
        })
        .filter_map(|interface| interface.bsd_name())
        // Interfaces can disappear during unplug/wake. A missing index must
        // never become an accepted route target.
        .filter_map(|name| interface_index(&name.to_string()).ok())
        .collect()
}

fn route_matches(
    actual: &RouteInfo,
    desired: &PlannedRoute,
    preferred_interface: Option<u16>,
    physical_interfaces: &HashSet<u16>,
) -> bool {
    // Talpid's DefaultNode chooses a gateway, not a binding to the preferred
    // interface. An encrypted peer route may legitimately use the other link
    // when Ethernet and Wi-Fi share a router. Tunnel destinations remain exact.
    actual.prefix == desired.prefix
        && actual.interface_index != 0
        && (preferred_interface == Some(actual.interface_index)
            || (matches!(desired.target, RouteTarget::PhysicalDefault)
                && physical_interfaces.contains(&actual.interface_index)))
}

fn route_conflicts(existing: &RouteInfo, desired: &PlannedRoute) -> bool {
    existing.prefix == desired.prefix && !existing.was_cloned
}

pub async fn remove_route_clones(
    manager: &RouteManagerHandle,
    desired: &[PlannedRoute],
) -> Result<()> {
    const MAX_REMOVALS: usize = 3;

    for route in desired {
        if route.prefix.prefix() == 0 || !matches!(&route.target, RouteTarget::Tunnel { .. }) {
            continue;
        }
        for _ in 0..MAX_REMOVALS {
            let removed = manager
                .remove_cloned_route(route.prefix)
                .await
                .map_err(|error| {
                    AppError::Platform(format!(
                        "cannot remove kernel-cloned route {}: {error}",
                        route.prefix
                    ))
                })?;
            if !removed {
                break;
            }
        }

        if let Some(existing) = inspect_route(manager, route.prefix).await?
            && existing.prefix == route.prefix
        {
            let message = if existing.was_cloned {
                format!(
                    "kernel-cloned route {} could not be cleared from interface {}",
                    route.prefix,
                    interface_label(existing.interface_index)
                )
            } else {
                format!(
                    "refusing to replace pre-existing route {} on interface {}",
                    route.prefix,
                    interface_label(existing.interface_index)
                )
            };
            return Err(verification_error(message));
        }
    }
    Ok(())
}

pub async fn verify_routes_removed(
    manager: &RouteManagerHandle,
    routes: &[crate::journal::JournalRoute],
    physical_v4: Option<u16>,
    physical_v6: Option<u16>,
) -> Result<()> {
    let physical_interfaces = physical_interface_indices();
    for route in routes {
        let prefix: IpNetwork = route
            .prefix
            .parse()
            .map_err(|error| AppError::Runtime(format!("invalid route in journal: {error}")))?;
        let Some(actual) = inspect_route(manager, prefix).await? else {
            continue;
        };
        let physical_default = if prefix.is_ipv4() {
            physical_v4
        } else {
            physical_v6
        };
        if route_was_removed(&actual, prefix, physical_default, &physical_interfaces) {
            continue;
        }
        return Err(verification_error(format!(
            "stale route {prefix} remains on interface {}",
            interface_label(actual.interface_index)
        )));
    }
    Ok(())
}

fn route_was_removed(
    actual: &RouteInfo,
    removed_prefix: IpNetwork,
    physical_default: Option<u16>,
    physical_interfaces: &HashSet<u16>,
) -> bool {
    if removed_prefix.prefix() == 0 {
        return actual.interface_index != 0 && physical_default == Some(actual.interface_index);
    }
    if actual.prefix != removed_prefix {
        return true;
    }
    // Restoring physical routes can recreate an endpoint's kernel cache entry
    // before recovery reads it back. It is not a leftover SimpleVPN route, even
    // when macOS chooses Wi-Fi while Ethernet is the preferred default. Keep
    // rejecting exact static routes and clones that still point into a tunnel.
    actual.was_cloned
        && actual.interface_index != 0
        && (physical_default == Some(actual.interface_index)
            || physical_interfaces.contains(&actual.interface_index))
}

async fn inspect_route(
    manager: &RouteManagerHandle,
    prefix: IpNetwork,
) -> Result<Option<RouteInfo>> {
    manager
        .get_route(prefix)
        .await
        .map_err(|error| AppError::Platform(format!("cannot inspect route {prefix}: {error}")))
}

fn interface_index(interface: &str) -> Result<u16> {
    let interface = CString::new(interface)
        .map_err(|_| verification_error("interface name contains a NUL byte"))?;
    // SAFETY: `interface` is a valid NUL-terminated C string.
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if index == 0 {
        return Err(verification_error(format!(
            "interface {} has no kernel index",
            interface.to_string_lossy()
        )));
    }
    u16::try_from(index).map_err(|_| verification_error("interface index exceeds 16 bits"))
}

fn interface_label(index: u16) -> String {
    let mut name = [0_i8; libc::IF_NAMESIZE];
    // SAFETY: `name` is a writable IF_NAMESIZE buffer and the returned pointer
    // is either null or points into that buffer as a NUL-terminated string.
    let result = unsafe { libc::if_indextoname(u32::from(index), name.as_mut_ptr()) };
    if result.is_null() {
        return format!("index {index}");
    }
    // SAFETY: successful `if_indextoname` always NUL-terminates the buffer.
    unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn parse_interface(output: &str) -> Result<InterfaceState> {
    let first = output
        .lines()
        .next()
        .ok_or_else(|| verification_error("ifconfig returned no interface state"))?;
    let up = first
        .split_once('<')
        .and_then(|(_, flags)| flags.split_once('>'))
        .is_some_and(|(flags, _)| flags.split(',').any(|flag| flag == "UP"));
    let mtu = first
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|pair| {
            (pair[0] == "mtu")
                .then(|| pair[1].parse::<u16>().ok())
                .flatten()
        })
        .ok_or_else(|| verification_error("ifconfig output has no valid MTU"))?;
    let mut addresses = HashSet::new();
    for line in output.lines().map(str::trim) {
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.first().copied() {
            Some("inet") if fields.len() >= 2 => {
                let address = fields[1];
                let mask = fields
                    .windows(2)
                    .find_map(|pair| (pair[0] == "netmask").then_some(pair[1]))
                    .ok_or_else(|| verification_error("IPv4 address has no netmask"))?;
                let address: Ipv4Addr = address.parse().map_err(|error| {
                    verification_error(format!("invalid IPv4 interface address: {error}"))
                })?;
                let prefix = ipv4_mask_prefix(mask)?;
                addresses.insert(
                    IpNetwork::new(IpAddr::V4(address), prefix)
                        .map_err(|error| verification_error(error.to_string()))?,
                );
            }
            Some("inet6") if fields.len() >= 2 => {
                let address = fields[1];
                let prefix = fields
                    .windows(2)
                    .find_map(|pair| (pair[0] == "prefixlen").then_some(pair[1]))
                    .ok_or_else(|| verification_error("IPv6 address has no prefix length"))?;
                let address = address.split('%').next().unwrap_or(address);
                let address: Ipv6Addr = address.parse().map_err(|error| {
                    verification_error(format!("invalid IPv6 interface address: {error}"))
                })?;
                let prefix: u8 = prefix
                    .parse()
                    .map_err(|error| verification_error(format!("invalid IPv6 prefix: {error}")))?;
                addresses.insert(
                    IpNetwork::new(IpAddr::V6(address), prefix)
                        .map_err(|error| verification_error(error.to_string()))?,
                );
            }
            _ => {}
        }
    }
    Ok(InterfaceState { up, mtu, addresses })
}

fn ipv4_mask_prefix(mask: &str) -> Result<u8> {
    let value = if let Some(hex) = mask.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
            .map_err(|error| verification_error(format!("invalid IPv4 mask: {error}")))?
    } else {
        u32::from(
            mask.parse::<Ipv4Addr>()
                .map_err(|error| verification_error(format!("invalid IPv4 mask: {error}")))?,
        )
    };
    contiguous_prefix(u128::from(value), 32)
}

fn contiguous_prefix(value: u128, bits: u8) -> Result<u8> {
    let shifted = value << (128 - bits);
    let prefix = shifted.leading_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    if shifted != expected {
        return Err(verification_error("network mask is not contiguous"));
    }
    Ok(prefix.min(bits))
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
    use crate::planner::RoutePurpose;

    #[test]
    fn recovery_accepts_recreated_endpoint_clones_on_either_physical_link() {
        let physical = HashSet::from([14, 18]);
        for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
            let prefix = prefix.parse().unwrap();
            for interface_index in [14, 18] {
                let actual = RouteInfo {
                    prefix,
                    interface_index,
                    was_cloned: true,
                };
                assert!(route_was_removed(&actual, prefix, Some(18), &physical));
                assert!(route_was_removed(&actual, prefix, None, &physical));
                // The route manager may support a physical uplink absent from
                // System Configuration's interface inventory.
                assert!(route_was_removed(
                    &actual,
                    prefix,
                    Some(interface_index),
                    &HashSet::new()
                ));
            }
        }
    }

    #[test]
    fn recovery_rejects_static_routes_and_clones_on_tunnel_or_unknown_interfaces() {
        let physical = HashSet::from([14, 18]);
        for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
            let prefix = prefix.parse().unwrap();
            for interface_index in [0, 14, 18, 22, 999] {
                let actual = RouteInfo {
                    prefix,
                    interface_index,
                    was_cloned: false,
                };
                assert!(!route_was_removed(&actual, prefix, Some(18), &physical));
                if !physical.contains(&interface_index) {
                    let cloned = RouteInfo {
                        was_cloned: true,
                        ..actual
                    };
                    assert!(!route_was_removed(&cloned, prefix, Some(18), &physical));
                }
            }
        }
    }

    #[test]
    fn recovery_accepts_covering_routes_and_requires_restored_physical_defaults() {
        let physical = HashSet::from([14, 18]);
        for (host, default) in [("192.0.2.1/32", "0.0.0.0/0"), ("2001:db8::1/128", "::/0")] {
            let host = host.parse().unwrap();
            let default = default.parse().unwrap();
            let actual = RouteInfo {
                prefix: default,
                interface_index: 18,
                was_cloned: false,
            };
            assert!(route_was_removed(&actual, host, Some(18), &physical));
            assert!(route_was_removed(&actual, default, Some(18), &physical));
            for interface_index in [0, 14, 22] {
                let other = RouteInfo {
                    interface_index,
                    ..actual
                };
                assert!(!route_was_removed(&other, default, Some(18), &physical));
            }
            assert!(!route_was_removed(&actual, default, None, &physical));
        }
    }

    #[test]
    fn endpoint_route_can_use_wifi_while_ethernet_is_preferred() {
        for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
            let prefix = prefix.parse().unwrap();
            let desired = PlannedRoute {
                prefix,
                target: RouteTarget::PhysicalDefault,
                purpose: RoutePurpose::EndpointException,
            };
            let actual = RouteInfo {
                prefix,
                interface_index: 14, // en0; preferred en7 is index 18.
                was_cloned: false,
            };
            let physical = HashSet::from([14, 18]);
            assert!(route_matches(&actual, &desired, Some(18), &physical));
            assert!(route_matches(&actual, &desired, None, &physical));
            // Other platform-supported uplinks still work via Talpid's default.
            assert!(route_matches(&actual, &desired, Some(14), &HashSet::new()));
        }
    }

    #[test]
    fn endpoint_verification_rejects_missing_unknown_and_tunnel_interfaces_and_wrong_prefixes() {
        let desired = PlannedRoute {
            prefix: "192.0.2.1/32".parse().unwrap(),
            target: RouteTarget::PhysicalDefault,
            purpose: RoutePurpose::EndpointException,
        };
        let physical = HashSet::from([14, 18]);
        for interface_index in [0, 1, 22, 999] {
            let actual = RouteInfo {
                prefix: desired.prefix,
                interface_index,
                was_cloned: false,
            };
            assert!(!route_matches(&actual, &desired, Some(18), &physical));
        }
        let covering_route = RouteInfo {
            prefix: "0.0.0.0/0".parse().unwrap(),
            interface_index: 14,
            was_cloned: false,
        };
        assert!(!route_matches(
            &covering_route,
            &desired,
            Some(18),
            &physical
        ));
    }

    #[test]
    fn tunnel_routes_still_require_the_exact_assigned_interface() {
        let desired = PlannedRoute {
            prefix: "192.0.2.0/24".parse().unwrap(),
            target: RouteTarget::Tunnel {
                profile: "work".into(),
                interface: "utun5".into(),
            },
            purpose: RoutePurpose::AllowedIp,
        };
        let physical = HashSet::from([14, 18]);
        for interface_index in [0, 14, 18, 22, 23] {
            let actual = RouteInfo {
                prefix: desired.prefix,
                interface_index,
                was_cloned: false,
            };
            assert_eq!(
                route_matches(&actual, &desired, Some(23), &physical),
                interface_index == 23
            );
        }
    }

    #[test]
    fn parses_ifconfig_state() {
        let state = parse_interface(
            "utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n\
             \tinet 10.0.0.2 --> 10.0.0.2 netmask 0xffffffff\n\
             \tinet6 fd00::2 prefixlen 64\n",
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(state.up);
        assert_eq!(state.mtu, 1380);
        assert!(state.addresses.contains(&"10.0.0.2/32".parse().unwrap()));
        assert!(state.addresses.contains(&"fd00::2/64".parse().unwrap()));
    }

    #[test]
    fn typed_route_conflicts_ignore_kernel_clones_but_preserve_static_routes() {
        let prefix = "192.0.2.1/32".parse().unwrap();
        let physical = PlannedRoute {
            prefix,
            target: RouteTarget::PhysicalDefault,
            purpose: RoutePurpose::EndpointException,
        };
        let tunnel = PlannedRoute {
            prefix,
            target: RouteTarget::Tunnel {
                profile: "work".to_owned(),
                interface: "utun9".to_owned(),
            },
            purpose: RoutePurpose::AllowedIp,
        };
        let cloned = RouteInfo {
            prefix,
            interface_index: 7,
            was_cloned: true,
        };
        let static_route = RouteInfo {
            was_cloned: false,
            ..cloned
        };

        assert!(!route_conflicts(&cloned, &physical));
        assert!(route_conflicts(&static_route, &physical));
        assert!(!route_conflicts(&cloned, &tunnel));
        assert!(route_conflicts(&static_route, &tunnel));
    }
}
