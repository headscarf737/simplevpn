// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::{
    collections::HashMap,
    env,
    ffi::CString,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const RUNTIME_DIRECTORY: &str = "/var/run/simplevpn";
const CONTROL_SOCKET: &str = "/var/run/simplevpn/control.sock";
const STATUS_FILE: &str = "/var/run/simplevpn/status.json";
const RECOVERY_DIRECTORY: &str = "/Library/Application Support/SimpleVPN";
const RECOVERY_JOURNAL: &str = "/Library/Application Support/SimpleVPN/recovery.json";
static NETWORK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Cleanup(&'static str);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new(self.0).args(["down", "--all"]).status();
    }
}

#[tokio::test]
#[ignore = "requires root, two reachable WireGuard peers, and a disposable macOS host"]
async fn concurrent_split_and_full_tunnels_transition_and_clean_up() {
    let _network_lock = NETWORK_TEST_LOCK.lock().await;
    assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
    assert_eq!(
        env::var("SIMPLEVPN_RUN_ROOT_TESTS").as_deref(),
        Ok("1"),
        "set SIMPLEVPN_RUN_ROOT_TESTS=1 to acknowledge host network mutation"
    );
    let binary = env!("CARGO_BIN_EXE_simplevpn");
    let _cleanup = Cleanup(binary);
    let route_observer = talpid_routing::RouteManagerHandle::spawn()
        .await
        .unwrap_or_else(|error| panic!("cannot start route observer: {error}"));
    let split = PathBuf::from(
        env::var_os("SIMPLEVPN_SPLIT_PROFILE")
            .unwrap_or_else(|| panic!("SIMPLEVPN_SPLIT_PROFILE is required")),
    );
    let full = PathBuf::from(
        env::var_os("SIMPLEVPN_FULL_PROFILE")
            .unwrap_or_else(|| panic!("SIMPLEVPN_FULL_PROFILE is required")),
    );

    run(binary, &["down", "--all"]);
    assert!(!pf_anchor_present());
    let orphan_cleanup_pf_state = pf_enabled();
    seed_orphaned_pf_references();
    assert!(pf_anchor_present());
    run(binary, &["down", "--all"]);
    assert!(!pf_anchor_present());
    assert_eq!(pf_enabled(), orphan_cleanup_pf_state);
    let baseline_dns = command_output("/usr/sbin/scutil", &["--dns"]);
    let baseline_pf = pf_enabled();
    let profile_dns = [split.as_path(), full.as_path()]
        .into_iter()
        .filter_map(read_profile_dns)
        .collect::<HashMap<_, _>>();

    assert!(
        Command::new(binary)
            .arg("up")
            .arg(&split)
            .status()
            .is_ok_and(|s| s.success())
    );
    assert!(
        Command::new(binary)
            .arg("up")
            .arg(&full)
            .status()
            .is_ok_and(|s| s.success())
    );
    let status = Command::new(binary)
        .args(["status", "--json"])
        .output()
        .unwrap_or_else(|error| panic!("status failed: {error}"));
    assert!(status.status.success());
    let json: serde_json::Value = serde_json::from_slice(&status.stdout)
        .unwrap_or_else(|error| panic!("invalid status JSON: {error}"));
    assert_eq!(json["profiles"].as_array().map(Vec::len), Some(2));
    let mut installed = Vec::new();
    for profile in json["profiles"]
        .as_array()
        .unwrap_or_else(|| panic!("profiles is not an array"))
    {
        let interface = profile["interface"]
            .as_str()
            .unwrap_or_else(|| panic!("profile has no interface"));
        let interface_index = interface_index(interface);
        let ifconfig = command_output("/sbin/ifconfig", &[interface]);
        assert!(
            ifconfig
                .lines()
                .next()
                .is_some_and(|line| line.contains("<UP,"))
        );
        for route in profile["routes"]
            .as_array()
            .unwrap_or_else(|| panic!("routes is not an array"))
        {
            if route["installed"] == true {
                let prefix = route["cidr"]
                    .as_str()
                    .unwrap_or_else(|| panic!("route has no CIDR"));
                assert_route_interface(&route_observer, prefix, interface_index).await;
                installed.push((prefix.to_owned(), interface.to_owned(), interface_index));
            }
        }
    }
    let dns_owner = json["dns_owner"]
        .as_str()
        .unwrap_or_else(|| panic!("active profiles have no DNS owner"));
    let dns_state = command_output("/usr/sbin/scutil", &["--dns"]);
    for server in profile_dns
        .get(dns_owner)
        .unwrap_or_else(|| panic!("DNS owner profile is unknown"))
    {
        assert!(
            dns_state.lines().any(|line| {
                line.trim()
                    .strip_prefix("nameserver[")
                    .and_then(|line| line.split_once(" : "))
                    .is_some_and(|(_, actual)| actual == server)
            }),
            "DNS server {server} is not active"
        );
    }
    assert!(pf_enabled());
    let pf_rules = command_output("/sbin/pfctl", &["-a", "simplevpn", "-sr"]);
    assert_leak_protection_rules(&pf_rules);
    assert!(pf_rules.lines().any(|line| line.contains("block")));
    assert!(pf_rules.lines().any(|line| line.contains("pass")));
    let scrub_rules = command_output("/sbin/pfctl", &["-a", "simplevpn-scrub", "-sr"]);
    assert_eq!(
        scrub_rules
            .lines()
            .filter(|line| line.contains("scrub"))
            .count(),
        1
    );
    verify_metadata(RUNTIME_DIRECTORY, 0o755);
    verify_metadata(CONTROL_SOCKET, 0o666);
    verify_metadata(STATUS_FILE, 0o644);
    verify_metadata(RECOVERY_DIRECTORY, 0o700);
    verify_metadata(RECOVERY_JOURNAL, 0o600);
    let journal: serde_json::Value = serde_json::from_slice(
        &fs::read(RECOVERY_JOURNAL).unwrap_or_else(|error| panic!("cannot read journal: {error}")),
    )
    .unwrap_or_else(|error| panic!("invalid journal JSON: {error}"));
    assert_eq!(journal["dirty"], true);
    let journal_text = journal.to_string();
    assert!(!journal_text.contains("private_key"));
    assert!(!journal_text.contains("preshared_key"));

    assert!(
        Command::new(binary)
            .args(["down", "--all"])
            .status()
            .is_ok_and(|s| s.success())
    );
    let final_status = Command::new(binary)
        .args(["status", "--json"])
        .output()
        .unwrap_or_else(|error| panic!("final status failed: {error}"));
    assert!(final_status.status.success());
    let json: serde_json::Value = serde_json::from_slice(&final_status.stdout)
        .unwrap_or_else(|error| panic!("invalid final status JSON: {error}"));
    assert_eq!(json["profiles"].as_array().map(Vec::len), Some(0));
    assert_eq!(json["dns_owner"], serde_json::Value::Null);
    for (prefix, interface, interface_index) in installed {
        assert_route_not_on_interface(&route_observer, &prefix, interface_index).await;
        let ifconfig = Command::new("/sbin/ifconfig")
            .arg(&interface)
            .output()
            .unwrap_or_else(|error| panic!("cannot inspect removed interface: {error}"));
        assert!(
            !ifconfig.status.success(),
            "interface {interface} still exists"
        );
    }
    assert_eq!(command_output("/usr/sbin/scutil", &["--dns"]), baseline_dns);
    assert_eq!(pf_enabled(), baseline_pf);
    assert!(!pf_anchor_present());
    let journal: serde_json::Value = serde_json::from_slice(
        &fs::read(RECOVERY_JOURNAL).unwrap_or_else(|error| panic!("cannot read journal: {error}")),
    )
    .unwrap_or_else(|error| panic!("invalid journal JSON: {error}"));
    assert_eq!(journal["dirty"], false);
    route_observer.stop().await;
}

#[tokio::test]
#[ignore = "requires root, site/internet profiles, and a disposable macOS host"]
async fn site_and_internet_modes_transition_and_restore_network() {
    let _network_lock = NETWORK_TEST_LOCK.lock().await;
    assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
    assert_eq!(env::var("SIMPLEVPN_RUN_ROOT_TESTS").as_deref(), Ok("1"));
    let binary = env!("CARGO_BIN_EXE_simplevpn");
    let site = env::var("SIMPLEVPN_SITE_PROFILE").expect("SIMPLEVPN_SITE_PROFILE is required");
    let internet =
        env::var("SIMPLEVPN_INTERNET_PROFILE").expect("SIMPLEVPN_INTERNET_PROFILE is required");
    let site_subnet = env::var("SIMPLEVPN_SITE_SUBNET").expect("SIMPLEVPN_SITE_SUBNET is required");
    let subnet: ipnetwork::Ipv4Network = site_subnet
        .parse()
        .expect("SIMPLEVPN_SITE_SUBNET must be an IPv4 CIDR");
    assert!(
        subnet.prefix() > 0,
        "the site subnet must be more specific than the default route"
    );
    assert_eq!(
        subnet.ip(),
        subnet.network(),
        "use a normalized site subnet"
    );
    let site_search_domain =
        env::var("SIMPLEVPN_SITE_SEARCH_DOMAIN").expect("SIMPLEVPN_SITE_SEARCH_DOMAIN is required");
    assert!(
        !site_search_domain.trim().is_empty(),
        "the site search domain must not be empty"
    );
    let (site_name, site_dns) = read_profile_dns(Path::new(&site)).unwrap();
    let (internet_name, internet_dns) = read_profile_dns(Path::new(&internet)).unwrap();
    assert_ne!(site_name, internet_name);
    let _cleanup = Cleanup(binary);
    run(binary, &["down", "--all"]);
    let baseline_dns = command_output("/usr/sbin/scutil", &["--dns"]);
    let baseline_pf = pf_enabled();
    let observer = talpid_routing::RouteManagerHandle::spawn().await.unwrap();
    for site_first in [true, false] {
        let (first, second) = if site_first {
            (&site, &internet)
        } else {
            (&internet, &site)
        };
        run(binary, &["up", first]);
        assert_site_internet_mode(
            binary,
            &observer,
            site_first.then_some((&site_name, &site_dns)),
            (!site_first).then_some((&internet_name, &internet_dns)),
            &site_subnet,
            &site_search_domain,
        )
        .await;
        run(binary, &["up", second]);
        assert_site_internet_mode(
            binary,
            &observer,
            Some((&site_name, &site_dns)),
            Some((&internet_name, &internet_dns)),
            &site_subnet,
            &site_search_domain,
        )
        .await;
        // Exercise removing either tunnel from the combined mode.
        run(binary, &["down", &internet_name]);
        assert_site_internet_mode(
            binary,
            &observer,
            Some((&site_name, &site_dns)),
            None,
            &site_subnet,
            &site_search_domain,
        )
        .await;
        run(binary, &["up", &internet]);
        run(binary, &["down", &site_name]);
        assert_site_internet_mode(
            binary,
            &observer,
            None,
            Some((&internet_name, &internet_dns)),
            &site_subnet,
            &site_search_domain,
        )
        .await;
        let last = status_json(binary);
        let last_interface = last["profiles"][0]["interface"].as_str().unwrap();
        run(binary, &["down", "--all"]);
        assert_eq!(status_json(binary)["profiles"].as_array().unwrap().len(), 0);
        assert_eq!(command_output("/usr/sbin/scutil", &["--dns"]), baseline_dns);
        assert_eq!(pf_enabled(), baseline_pf);
        assert!(!pf_anchor_present());
        assert!(
            !Command::new("/sbin/ifconfig")
                .arg(last_interface)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    observer.stop().await;
}

fn status_json(binary: &str) -> serde_json::Value {
    serde_json::from_str(&command_output(binary, &["status", "--json"])).unwrap()
}

async fn assert_site_internet_mode(
    binary: &str,
    observer: &talpid_routing::RouteManagerHandle,
    site: Option<(&str, &[String])>,
    internet: Option<(&str, &[String])>,
    site_subnet: &str,
    site_search_domain: &str,
) {
    let status = status_json(binary);
    let profiles = status["profiles"].as_array().unwrap();
    assert_eq!(
        profiles.len(),
        usize::from(site.is_some()) + usize::from(internet.is_some())
    );
    let dns_owner = site.or(internet).unwrap();
    let default_owner = internet.or(site).unwrap().0;
    assert_eq!(status["dns_owner"], dns_owner.0);
    for profile in profiles {
        assert_eq!(profile["state"], "connected");
        let name = profile["name"].as_str().unwrap();
        let index = interface_index(profile["interface"].as_str().unwrap());
        for cidr in ["0.0.0.0/0", "::/0"] {
            let route = profile["routes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["cidr"] == cidr)
                .unwrap();
            let blocked = cidr == "::/0" && internet.is_none();
            assert_eq!(route["installed"], name == default_owner && !blocked);
            assert_eq!(
                route["blocked"].as_bool().unwrap_or(false),
                name == default_owner && blocked
            );
            if name == default_owner && !blocked {
                assert_route_interface(observer, cidr, index).await;
            }
        }
        if site.is_some_and(|(site_name, _)| site_name == name) {
            assert_route_interface(observer, site_subnet, index).await;
        }
        if name == dns_owner.0 {
            for server in dns_owner.1 {
                let suffix = if server.contains(':') { 128 } else { 32 };
                assert_route_interface(observer, &format!("{server}/{suffix}"), index).await;
            }
        }
    }
    let dns = command_output("/usr/sbin/scutil", &["--dns"]);
    for server in dns_owner.1 {
        assert!(dns.lines().any(|line| {
            line.trim()
                .strip_prefix("nameserver[")
                .and_then(|line| line.split_once(" : "))
                .is_some_and(|(_, actual)| actual == server)
        }));
    }
    if site.is_some() {
        assert!(dns.contains(site_search_domain));
    }
    let rules = command_output("/sbin/pfctl", &["-a", "simplevpn", "-sr"]);
    assert_leak_protection_rules(&rules);
    assert!(
        rules
            .lines()
            .any(|line| line.contains("block") && line.contains("out"))
    );
    let ipv6_block = rules
        .lines()
        .any(|line| line.contains("block") && line.contains("inet6"));
    assert_eq!(ipv6_block, internet.is_none());
}

fn assert_leak_protection_rules(rules: &str) {
    let mut endpoints = 0;
    for rule in rules.lines().filter(|rule| {
        rule.starts_with("pass out")
            && rule.contains("proto udp")
            && rule.contains("keep state")
            && !rule.contains(" on ")
    }) {
        assert!(
            rule.contains("user = root") || rule.contains("user = 0"),
            "endpoint exception must require a root-owned socket: {rule}"
        );
        endpoints += 1;
    }
    assert!(endpoints > 0, "no endpoint exceptions found in PF rules");
    for rule in rules.lines().filter(|rule| rule.starts_with("pass")) {
        if rule.contains(" on utun") || rule.contains("port = 53") || rule.contains("port = domain")
        {
            assert!(
                rule.contains("no state"),
                "interface/DNS pass can float: {rule}"
            );
        }
    }
}

fn run(binary: &str, arguments: &[&str]) {
    assert!(
        Command::new(binary)
            .args(arguments)
            .status()
            .is_ok_and(|status| status.success()),
        "simplevpn {arguments:?} failed"
    );
}

fn command_output(command: &str, arguments: &[&str]) -> String {
    let output = Command::new(command)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("cannot execute {command}: {error}"));
    assert!(
        output.status.success(),
        "{command} {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("non-UTF-8 output: {error}"))
}

fn read_profile_dns(path: &Path) -> Option<(String, Vec<String>)> {
    let profile: toml::Value = toml::from_str(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("invalid profile {}: {error}", path.display()));
    let name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| panic!("profile has no valid filename"))
        .to_owned();
    let servers = profile
        .get("dns")?
        .get("servers")?
        .as_array()?
        .iter()
        .map(|server| {
            server
                .as_str()
                .unwrap_or_else(|| panic!("DNS server is not a string"))
                .to_owned()
        })
        .collect();
    Some((name, servers))
}

fn interface_index(interface: &str) -> u16 {
    let interface = CString::new(interface).unwrap_or_else(|_| panic!("invalid interface name"));
    // SAFETY: `interface` is a valid NUL-terminated C string.
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    assert_ne!(index, 0, "interface has no kernel index");
    u16::try_from(index).unwrap_or_else(|_| panic!("interface index exceeds 16 bits"))
}

async fn assert_route_interface(
    routes: &talpid_routing::RouteManagerHandle,
    prefix: &str,
    interface_index: u16,
) {
    let network: ipnetwork::IpNetwork = prefix
        .parse()
        .unwrap_or_else(|error| panic!("invalid route {prefix}: {error}"));
    let route = routes
        .get_route(network)
        .await
        .unwrap_or_else(|error| panic!("cannot inspect route {prefix}: {error}"))
        .unwrap_or_else(|| panic!("route {prefix} is missing"));
    assert_eq!(route.prefix, network, "route {prefix} resolved differently");
    assert_eq!(
        route.interface_index, interface_index,
        "route {prefix} is installed on the wrong interface"
    );
}

async fn assert_route_not_on_interface(
    routes: &talpid_routing::RouteManagerHandle,
    prefix: &str,
    interface_index: u16,
) {
    let network: ipnetwork::IpNetwork = prefix
        .parse()
        .unwrap_or_else(|error| panic!("invalid route {prefix}: {error}"));
    let route = routes
        .get_route(network)
        .await
        .unwrap_or_else(|error| panic!("cannot inspect route {prefix}: {error}"));
    assert!(
        route.is_none_or(|route| {
            route.prefix != network || route.interface_index != interface_index
        }),
        "route {prefix} still uses interface index {interface_index}"
    );
}

fn pf_enabled() -> bool {
    command_output("/sbin/pfctl", &["-s", "info"])
        .lines()
        .find_map(|line| line.strip_prefix("Status: "))
        .is_some_and(|status| status.starts_with("Enabled"))
}

fn pf_anchor_present() -> bool {
    let root_filter = command_output("/sbin/pfctl", &["-sr"]);
    let root_nat = command_output("/sbin/pfctl", &["-sn"]);
    ["simplevpn", "simplevpn-scrub"].iter().any(|anchor| {
        let exact = format!("\"{anchor}\"");
        let descendants = format!("\"{anchor}/*\"");
        root_filter.contains(&exact)
            || root_filter.contains(&descendants)
            || root_nat.contains(&exact)
            || root_nat.contains(&descendants)
            || !command_output("/sbin/pfctl", &["-a", anchor, "-sr"])
                .trim()
                .is_empty()
            || !command_output("/sbin/pfctl", &["-a", anchor, "-sn"])
                .trim()
                .is_empty()
    })
}

fn seed_orphaned_pf_references() {
    let mut pf = pfctl::PfCtl::new().unwrap_or_else(|error| panic!("cannot open PF: {error}"));
    pf.try_add_anchor("simplevpn", pfctl::AnchorKind::Filter)
        .unwrap_or_else(|error| panic!("cannot seed filter anchor: {error}"));
    pf.try_add_anchor("simplevpn-scrub", pfctl::AnchorKind::Scrub)
        .unwrap_or_else(|error| panic!("cannot seed scrub anchor: {error}"));
}

fn verify_metadata(path: &str, mode: u32) {
    let metadata =
        fs::symlink_metadata(path).unwrap_or_else(|error| panic!("cannot inspect {path}: {error}"));
    assert!(!metadata.file_type().is_symlink(), "{path} is a symlink");
    assert_eq!(metadata.uid(), 0, "{path} is not root-owned");
    assert_eq!(metadata.permissions().mode() & 0o777, mode, "{path} mode");
}
