// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::IpAddr;

use ipnetwork::IpNetwork;

// Detect complete coverage even when a default is expressed as several CIDRs.
// Sorting and merging inclusive ranges handles overlap without double-counting,
// and avoids overflowing on the IPv6 /0 range.
pub fn covers_family(routes: impl IntoIterator<Item = IpNetwork>, ipv6: bool) -> bool {
    let mut ranges: Vec<_> = routes
        .into_iter()
        .filter(|route| route.is_ipv6() == ipv6)
        .map(|route| {
            let (start, bits) = match route.network() {
                IpAddr::V4(address) => (u128::from(u32::from(address)), 32),
                IpAddr::V6(address) => (u128::from(address), 128),
            };
            let host_bits = bits - u32::from(route.prefix());
            let mask = u128::MAX.checked_shr(128 - host_bits).unwrap_or(0);
            (start, start | mask)
        })
        .collect();
    ranges.sort_unstable();
    let last = if ipv6 {
        u128::MAX
    } else {
        u128::from(u32::MAX)
    };
    let mut next = 0;
    for (start, end) in ranges {
        if start > next {
            return false;
        }
        if end == last {
            return true;
        }
        next = next.max(end + 1);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_full_coverage_without_overflow_or_double_counting() {
        for (routes, ipv6, expected) in [
            (vec!["0.0.0.0/0"], false, true),
            (vec!["::/0"], true, true),
            (vec!["128.0.0.0/1", "0.0.0.0/1"], false, true),
            (vec!["::/1", "8000::/2", "c000::/2"], true, true),
            (vec!["0.0.0.0/1", "0.0.0.0/1"], false, false),
            (vec!["0.0.0.0/1", "64.0.0.0/2"], false, false),
            (vec!["0.0.0.0/2", "128.0.0.0/1"], false, false),
            (vec!["0.0.0.0/0"], true, false),
            (vec!["::/0"], false, false),
            (vec!["::/1", "8000::/1", "::/128"], true, true),
            (vec!["255.255.255.255/32"], false, false),
            (vec![], true, false),
        ] {
            assert_eq!(
                covers_family(routes.iter().map(|route| route.parse().unwrap()), ipv6),
                expected,
                "{routes:?}"
            );
        }
    }
}
