// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs::OpenOptions, io::Read, net::IpAddr, os::unix::fs::OpenOptionsExt, path::Path, str::FromStr,
};

use ipnetwork::IpNetwork;
use zeroize::Zeroizing;

use crate::{
    AppError, Result,
    config::{
        DnsConfig, Endpoint, InterfaceConfig, PeerConfig, Profile, ProfileFile, PublicKey,
        SecretKey, validate_search_domain,
    },
};

const MAX_WG_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Default)]
struct InterfaceBuilder {
    private_key: Option<SecretKey>,
    addresses: Vec<IpNetwork>,
    dns_servers: Vec<IpAddr>,
    dns_search_domains: Vec<String>,
    mtu: Option<u16>,
    listen_port: Option<u16>,
}

#[derive(Default)]
struct PeerBuilder {
    public_key: Option<PublicKey>,
    preshared_key: Option<SecretKey>,
    endpoint: Option<Endpoint>,
    allowed_ips: Vec<IpNetwork>,
    persistent_keepalive: Option<u16>,
}

#[derive(Clone, Copy)]
enum Section {
    None,
    Interface,
    Peer(usize),
}

pub fn convert(path: &Path, priority: i32) -> Result<Zeroizing<String>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            config_error(format!(
                "cannot open WireGuard config {}: {error}",
                path.display()
            ))
        })?;
    let metadata = file.metadata().map_err(|error| {
        config_error(format!(
            "cannot inspect WireGuard config {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(config_error(format!(
            "WireGuard config {} must be a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_WG_CONFIG_BYTES {
        return Err(config_error(format!(
            "WireGuard config {} exceeds the 1 MiB limit",
            path.display()
        )));
    }

    let mut contents = Zeroizing::new(String::new());
    file.by_ref()
        .take(MAX_WG_CONFIG_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| {
            config_error(format!(
                "cannot read WireGuard config {}: {error}",
                path.display()
            ))
        })?;
    if contents.len() as u64 > MAX_WG_CONFIG_BYTES {
        return Err(config_error(format!(
            "WireGuard config {} exceeds the 1 MiB limit",
            path.display()
        )));
    }

    let name = default_profile_name(path)?;
    let profile = parse(&contents, &name, priority)?;
    let encoded = toml::to_string_pretty(&ProfileFile::from(profile))
        .map_err(|error| AppError::Runtime(format!("cannot encode converted profile: {error}")))?;
    Ok(Zeroizing::new(encoded))
}

pub fn default_profile_name(path: &Path) -> Result<String> {
    path.file_stem()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            config_error(format!(
                "cannot derive a profile name from {}",
                path.display()
            ))
        })
}

fn parse(input: &str, name: &str, priority: i32) -> Result<Profile> {
    let mut interface = InterfaceBuilder::default();
    let mut peers = Vec::<PeerBuilder>::new();
    let mut section = Section::None;
    let mut saw_interface = false;

    for (index, source_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = source_line
            .split_once('#')
            .map_or(source_line, |(before, _)| before)
            .trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(line_error(line_number, "invalid section header"));
            }
            let section_name = line[1..line.len() - 1].trim();
            if section_name.eq_ignore_ascii_case("Interface") {
                if saw_interface {
                    return Err(line_error(
                        line_number,
                        "the [Interface] section may only occur once",
                    ));
                }
                if !peers.is_empty() {
                    return Err(line_error(
                        line_number,
                        "the [Interface] section must precede every [Peer] section",
                    ));
                }
                saw_interface = true;
                section = Section::Interface;
            } else if section_name.eq_ignore_ascii_case("Peer") {
                if !saw_interface {
                    return Err(line_error(
                        line_number,
                        "a [Peer] section cannot precede [Interface]",
                    ));
                }
                peers.push(PeerBuilder::default());
                section = Section::Peer(peers.len() - 1);
            } else {
                return Err(line_error(line_number, "unsupported section"));
            }
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| line_error(line_number, "expected key = value"))?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(line_error(
                line_number,
                "expected a non-empty key and value",
            ));
        }

        match section {
            Section::None => {
                return Err(line_error(
                    line_number,
                    "setting appears before a section header",
                ));
            }
            Section::Interface => parse_interface_setting(&mut interface, key, value, line_number)?,
            Section::Peer(peer) => {
                parse_peer_setting(&mut peers[peer], key, value, line_number)?;
            }
        }
    }

    if !saw_interface {
        return Err(config_error("WireGuard config has no [Interface] section"));
    }

    let private_key = interface
        .private_key
        .ok_or_else(|| config_error("[Interface] is missing PrivateKey"))?;
    let peers = peers
        .into_iter()
        .enumerate()
        .map(|(index, peer)| finish_peer(peer, index + 1))
        .collect::<Result<Vec<_>>>()?;
    let dns = if interface.dns_servers.is_empty() && interface.dns_search_domains.is_empty() {
        None
    } else {
        Some(DnsConfig {
            priority: None,
            servers: interface.dns_servers,
            search_domains: interface.dns_search_domains,
        })
    };

    Profile {
        version: 1,
        name: name.to_owned(),
        priority,
        interface: InterfaceConfig {
            private_key,
            addresses: interface.addresses,
            mtu: interface.mtu,
            listen_port: interface.listen_port.filter(|port| *port != 0),
        },
        dns,
        peers,
    }
    .validate()
}

fn parse_interface_setting(
    interface: &mut InterfaceBuilder,
    key: &str,
    value: &str,
    line: usize,
) -> Result<()> {
    if key.eq_ignore_ascii_case("PrivateKey") {
        set_once(
            &mut interface.private_key,
            SecretKey::parse(value)
                .map_err(|error| line_error(line, format!("invalid PrivateKey: {error}")))?,
            "PrivateKey",
            line,
        )
    } else if key.eq_ignore_ascii_case("Address") {
        interface
            .addresses
            .extend(parse_list(value, "Address", line, parse_network)?);
        Ok(())
    } else if key.eq_ignore_ascii_case("DNS") {
        parse_dns_entries(interface, value, line)?;
        Ok(())
    } else if key.eq_ignore_ascii_case("MTU") {
        let mtu = parse_number(value, "MTU", line)?;
        set_once(&mut interface.mtu, mtu, "MTU", line)
    } else if key.eq_ignore_ascii_case("ListenPort") {
        let port = parse_number(value, "ListenPort", line)?;
        set_once(&mut interface.listen_port, port, "ListenPort", line)
    } else if matches_ignore_ascii_case(
        key,
        &[
            "Table",
            "PreUp",
            "PostUp",
            "PreDown",
            "PostDown",
            "SaveConfig",
            "FwMark",
        ],
    ) {
        Err(line_error(
            line,
            format!("{key} has no equivalent in a simplevpn profile"),
        ))
    } else {
        Err(line_error(line, "unsupported [Interface] setting"))
    }
}

fn parse_peer_setting(peer: &mut PeerBuilder, key: &str, value: &str, line: usize) -> Result<()> {
    if key.eq_ignore_ascii_case("PublicKey") {
        set_once(
            &mut peer.public_key,
            PublicKey::parse(value)
                .map_err(|error| line_error(line, format!("invalid PublicKey: {error}")))?,
            "PublicKey",
            line,
        )
    } else if key.eq_ignore_ascii_case("PresharedKey") {
        set_once(
            &mut peer.preshared_key,
            SecretKey::parse(value)
                .map_err(|error| line_error(line, format!("invalid PresharedKey: {error}")))?,
            "PresharedKey",
            line,
        )
    } else if key.eq_ignore_ascii_case("Endpoint") {
        set_once(
            &mut peer.endpoint,
            Endpoint::parse(value)
                .map_err(|error| line_error(line, format!("invalid Endpoint: {error}")))?,
            "Endpoint",
            line,
        )
    } else if key.eq_ignore_ascii_case("AllowedIPs") {
        peer.allowed_ips
            .extend(parse_list(value, "AllowedIPs", line, parse_network)?);
        Ok(())
    } else if key.eq_ignore_ascii_case("PersistentKeepalive") {
        let keepalive = if value.eq_ignore_ascii_case("off") {
            0
        } else {
            parse_number(value, "PersistentKeepalive", line)?
        };
        set_once(
            &mut peer.persistent_keepalive,
            keepalive,
            "PersistentKeepalive",
            line,
        )
    } else {
        Err(line_error(line, "unsupported [Peer] setting"))
    }
}

fn finish_peer(peer: PeerBuilder, number: usize) -> Result<PeerConfig> {
    Ok(PeerConfig {
        public_key: peer
            .public_key
            .ok_or_else(|| config_error(format!("[Peer] #{number} is missing PublicKey")))?,
        preshared_key: peer.preshared_key,
        endpoint: peer
            .endpoint
            .ok_or_else(|| config_error(format!("[Peer] #{number} is missing Endpoint")))?,
        allowed_ips: peer.allowed_ips,
        persistent_keepalive: peer.persistent_keepalive.filter(|seconds| *seconds != 0),
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &str, line: usize) -> Result<()> {
    if slot.is_some() {
        return Err(line_error(line, format!("duplicate {key} setting")));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_list<T>(
    value: &str,
    key: &str,
    line: usize,
    parse_item: fn(&str, &str, usize) -> Result<T>,
) -> Result<Vec<T>> {
    value
        .split(',')
        .map(str::trim)
        .map(|item| {
            if item.is_empty() {
                Err(line_error(line, format!("{key} contains an empty item")))
            } else {
                parse_item(item, key, line)
            }
        })
        .collect()
}

fn parse_network(value: &str, key: &str, line: usize) -> Result<IpNetwork> {
    IpNetwork::from_str(value).map_err(|_| line_error(line, format!("invalid {key} network")))
}

fn parse_dns_entries(interface: &mut InterfaceBuilder, value: &str, line: usize) -> Result<()> {
    for entry in value.split(',').map(str::trim) {
        if entry.is_empty() {
            return Err(line_error(line, "DNS contains an empty item"));
        }
        if let Ok(server) = IpAddr::from_str(entry) {
            interface.dns_servers.push(server);
        } else {
            validate_search_domain(entry).map_err(|error| line_error(line, error.to_string()))?;
            interface.dns_search_domains.push(entry.to_owned());
        }
    }
    Ok(())
}

fn parse_number<T>(value: &str, key: &str, line: usize) -> Result<T>
where
    T: FromStr,
{
    value
        .parse()
        .map_err(|_| line_error(line, format!("{key} must be an unsigned 16-bit integer")))
}

fn matches_ignore_ascii_case(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn line_error(line: usize, message: impl Into<String>) -> AppError {
    config_error(format!("WireGuard config line {line}: {}", message.into()))
}

fn config_error(message: impl Into<String>) -> AppError {
    AppError::Config(message.into())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::*;

    fn wg_config(extra_interface: &str, extra_peer: &str) -> String {
        format!(
            r#"# A normal wg-quick profile
[Interface]
PrivateKey = {}
Address = 10.0.0.2/32, fd00::2/128
DNS = 10.0.0.53, fd00::53, corp.example.com
MTU = 1380
ListenPort = 51820
{extra_interface}

[Peer]
PublicKey = {}
PresharedKey = {}
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
{extra_peer}
"#,
            STANDARD.encode([1_u8; 32]),
            STANDARD.encode([2_u8; 32]),
            STANDARD.encode([3_u8; 32]),
        )
    }

    #[test]
    fn converts_a_complete_wg_quick_profile() {
        let profile =
            parse(&wg_config("", ""), "work", 42).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(profile.version, 1);
        assert_eq!(profile.name, "work");
        assert_eq!(profile.priority, 42);
        assert_eq!(profile.interface.addresses.len(), 2);
        assert_eq!(profile.interface.listen_port, Some(51820));
        assert_eq!(profile.dns.as_ref().map(|dns| dns.servers.len()), Some(2));
        assert_eq!(
            profile.dns.as_ref().map(|dns| dns
                .search_domains
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()),
            Some(vec!["corp.example.com"])
        );
        assert_eq!(profile.peers.len(), 1);
        assert!(profile.peers[0].preshared_key.is_some());
        assert!(profile.is_full_tunnel());
        let encoded = toml::to_string_pretty(&ProfileFile::from(profile))
            .unwrap_or_else(|error| panic!("cannot encode converted profile: {error}"));
        assert!(encoded.contains("search_domains = [\"corp.example.com\"]"));
        assert!(!encoded.lines().any(|line| line.starts_with("name = ")));
    }

    #[test]
    fn accepts_repeated_list_settings_and_multiple_peers() {
        let private = STANDARD.encode([1_u8; 32]);
        let public_one = STANDARD.encode([2_u8; 32]);
        let public_two = STANDARD.encode([4_u8; 32]);
        let input = format!(
            r#"[Interface]
PrivateKey = {private}
Address = 10.0.0.2/32
Address = fd00::2/128

[Peer]
PublicKey = {public_one}
Endpoint = one.example.com:51820
AllowedIPs = 10.0.0.0/24

[Peer]
PublicKey = {public_two}
Endpoint = [2001:db8::1]:51820
AllowedIPs = fd00::/64
"#
        );
        let profile = parse(&input, "split", 0).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(profile.interface.addresses.len(), 2);
        assert_eq!(profile.peers.len(), 2);
    }

    #[test]
    fn rejects_wg_quick_behavior_that_cannot_be_preserved() {
        let error = parse(&wg_config("PostUp = route add something", ""), "work", 0)
            .expect_err("PostUp should not be discarded");
        assert!(error.to_string().contains("PostUp has no equivalent"));
    }

    #[test]
    fn key_errors_do_not_echo_secret_values() {
        let secret = "not-valid-but-sensitive";
        let input = wg_config("", "").replace(&STANDARD.encode([1_u8; 32]), secret);
        let error = parse(&input, "work", 0).expect_err("invalid key should fail");
        assert!(error.to_string().contains("canonical base64"));
        assert!(!error.to_string().contains(secret));
    }

    #[test]
    fn malformed_settings_do_not_echo_sensitive_text() {
        let secret = "sensitive_value_that_must_not_be_echoed";
        for input in [
            wg_config(&format!("{secret} = value"), ""),
            wg_config("", &format!("{secret} = value")),
            wg_config("", "").replace("[Interface]", &format!("[{secret}]")),
            wg_config("", "").replace("corp.example.com", secret),
            wg_config("", "").replace("10.0.0.2/32", secret),
        ] {
            let error = parse(&input, "work", 0).unwrap_err();
            assert!(!error.to_string().contains(secret));
        }
    }

    #[test]
    fn rejects_invalid_dns_search_domains() {
        let input = wg_config("", "").replace("corp.example.com", "not_a_domain");
        let error = parse(&input, "work", 0).expect_err("invalid search domain should fail");
        assert!(error.to_string().contains("invalid DNS search domain"));
    }

    #[test]
    fn converts_disabled_listen_port_and_keepalive_to_omitted_values() {
        let input = wg_config("", "").replace("ListenPort = 51820", "ListenPort = 0");
        let input = input.replace("PersistentKeepalive = 25", "PersistentKeepalive = off");
        let profile = parse(&input, "work", 0).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(profile.interface.listen_port, None);
        assert_eq!(profile.peers[0].persistent_keepalive, None);
    }

    #[test]
    fn converts_ipv6_allowed_ip_on_ipv4_only_interface() {
        let input = wg_config("", "").replace(
            "Address = 10.0.0.2/32, fd00::2/128",
            "Address = 10.0.0.2/32",
        );
        let input = input.replace("DNS = 10.0.0.53, fd00::53,", "DNS = 10.0.0.53,");
        let profile = parse(&input, "work", 0).unwrap_or_else(|error| panic!("{error}"));
        assert!(profile.peers[0].allowed_ips.iter().any(IpNetwork::is_ipv6));
        assert!(!profile.interface.addresses.iter().any(IpNetwork::is_ipv6));
    }

    #[test]
    fn derives_name_from_filename() {
        assert_eq!(
            default_profile_name(Path::new("/tmp/client.conf"))
                .unwrap_or_else(|error| panic!("{error}")),
            "client"
        );
    }
}
