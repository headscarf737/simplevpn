// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::{fs::MetadataExt, fs::OpenOptionsExt},
    path::Path,
    str::FromStr,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zeroize::{Zeroize, Zeroizing};

use crate::{AppError, Result};

const MAX_PROFILE_BYTES: u64 = 1024 * 1024;
const MIN_MTU: u16 = 576;
const MIN_IPV6_MTU: u16 = 1280;
const MAX_MTU: u16 = 9000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u8,
    pub name: String,
    pub priority: i32,
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    pub peers: Vec<PeerConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileFile {
    pub version: u8,
    pub priority: i32,
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    pub peers: Vec<PeerConfig>,
}

impl ProfileFile {
    pub(crate) fn into_profile(self, name: String) -> Result<Profile> {
        Profile {
            version: self.version,
            name,
            priority: self.priority,
            interface: self.interface,
            dns: self.dns,
            peers: self.peers,
        }
        .validate()
    }
}

impl From<Profile> for ProfileFile {
    fn from(profile: Profile) -> Self {
        Self {
            version: profile.version,
            priority: profile.priority,
            interface: profile.interface,
            dns: profile.dns,
            peers: profile.peers,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    pub private_key: SecretKey,
    pub addresses: Vec<IpNetwork>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub listen_port: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    pub servers: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub public_key: PublicKey,
    #[serde(default)]
    pub preshared_key: Option<SecretKey>,
    pub endpoint: Endpoint,
    pub allowed_ips: Vec<IpNetwork>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    pub fn parse(value: &str) -> Result<Self> {
        let (host, port) = split_host_port(value)?;
        validate_host(&host)?;
        Ok(Self { host, port })
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn display_authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl Serialize for Endpoint {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.display_authority())
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn parse(value: &str) -> Result<Self> {
        let bytes = parse_key(value)?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(config_error("public key must not be all zeroes"));
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<public-key>")
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        Self::parse(&encoded).map_err(de::Error::custom)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn parse(value: &str) -> Result<Self> {
        parse_key(value).map(Self)
    }

    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&Zeroizing::new(STANDARD.encode(self.0)))
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        Self::parse(&encoded).map_err(de::Error::custom)
    }
}

fn parse_key(encoded: &str) -> Result<[u8; 32]> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| config_error("key must be canonical base64"))?,
    );
    if decoded.len() != 32 {
        return Err(config_error("key must decode to exactly 32 bytes"));
    }
    if Zeroizing::new(STANDARD.encode(&decoded)).as_str() != encoded {
        return Err(config_error("key must use canonical padded base64"));
    }
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

impl Profile {
    pub fn load_secure(path: &Path, invoking_uid: u32) -> Result<Self> {
        let name = profile_name_from_path(path)?;
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AppError::Config(format!(
                "cannot inspect profile {}: {error}",
                path.display()
            ))
        })?;
        validate_metadata(path, &metadata, invoking_uid)?;

        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options.open(path).map_err(|error| {
            AppError::Config(format!(
                "cannot securely open profile {}: {error}",
                path.display()
            ))
        })?;
        let opened_metadata = file.metadata().map_err(|error| {
            AppError::Config(format!(
                "cannot inspect open profile {}: {error}",
                path.display()
            ))
        })?;
        validate_metadata(path, &opened_metadata, invoking_uid)?;
        if metadata.dev() != opened_metadata.dev() || metadata.ino() != opened_metadata.ino() {
            return Err(AppError::Config(format!(
                "profile {} changed while it was being opened",
                path.display()
            )));
        }

        Self::from_reader(file, path, name)
    }

    fn from_reader(file: File, path: &Path, name: String) -> Result<Self> {
        let mut contents = Zeroizing::new(String::new());
        file.take(MAX_PROFILE_BYTES + 1)
            .read_to_string(&mut contents)
            .map_err(|error| {
                AppError::Config(format!("cannot read profile {}: {error}", path.display()))
            })?;
        if contents.len() as u64 > MAX_PROFILE_BYTES {
            return Err(AppError::Config(format!(
                "profile {} exceeds the 1 MiB limit",
                path.display()
            )));
        }

        toml::from_str::<ProfileFile>(&contents)
            .map_err(sanitized_toml_error)
            .and_then(|profile| profile.into_profile(name))
    }

    #[cfg(test)]
    pub fn parse(input: &str) -> Result<Self> {
        toml::from_str::<ProfileFile>(input)
            .map_err(sanitized_toml_error)?
            .into_profile("work".to_owned())
    }

    pub fn validate(mut self) -> Result<Self> {
        if self.version != 1 {
            return Err(config_error("version must be exactly 1"));
        }
        validate_profile_name(&self.name)?;
        if self
            .interface
            .private_key
            .expose()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(config_error("interface private_key must not be all zeroes"));
        }
        if self.interface.addresses.is_empty() {
            return Err(config_error("interface.addresses must not be empty"));
        }
        if self.peers.is_empty() {
            return Err(config_error("at least one peer is required"));
        }
        if let Some(mtu) = self.interface.mtu {
            if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
                return Err(config_error(format!(
                    "interface.mtu must be between {MIN_MTU} and {MAX_MTU}"
                )));
            }
            if mtu < MIN_IPV6_MTU && self.interface.addresses.iter().any(IpNetwork::is_ipv6) {
                return Err(config_error(
                    "an IPv6 interface requires an MTU of at least 1280",
                ));
            }
        }
        if self.interface.listen_port == Some(0) {
            return Err(config_error("interface.listen_port must not be zero"));
        }

        let mut interface_addresses = HashSet::new();
        for address in &self.interface.addresses {
            validate_interface_address(*address)?;
            if !interface_addresses.insert(*address) {
                return Err(config_error(format!(
                    "duplicate interface address {address}"
                )));
            }
        }
        let has_ipv4_address = self.interface.addresses.iter().any(IpNetwork::is_ipv4);
        let has_ipv6_address = self.interface.addresses.iter().any(IpNetwork::is_ipv6);

        let mut public_keys = HashSet::new();
        let mut allowed_routes = HashSet::new();
        for peer in &mut self.peers {
            if !public_keys.insert(*peer.public_key.as_bytes()) {
                return Err(config_error("peer public keys must be unique"));
            }
            if peer
                .preshared_key
                .as_ref()
                .is_some_and(|key| key.expose().iter().all(|byte| *byte == 0))
            {
                return Err(config_error("peer preshared_key must not be all zeroes"));
            }
            if peer.allowed_ips.is_empty() {
                return Err(config_error(
                    "each peer must declare at least one allowed_ip",
                ));
            }
            if peer.persistent_keepalive == Some(0) {
                return Err(config_error("persistent_keepalive must not be zero"));
            }
            for route in &mut peer.allowed_ips {
                // Routing ownership is based on network prefixes, not host bits.
                // Otherwise equivalent CIDRs can bypass duplicate/priority checks.
                *route = IpNetwork::new(route.network(), route.prefix())
                    .map_err(|_| config_error("invalid allowed_ip prefix"))?;
                if route.is_ipv4() && !has_ipv4_address {
                    return Err(config_error(
                        "an IPv4 allowed_ip requires an IPv4 interface address",
                    ));
                }
                if !allowed_routes.insert(*route) {
                    return Err(config_error(format!(
                        "allowed route {route} occurs more than once in the profile"
                    )));
                }
            }
        }

        if let Some(dns) = &self.dns {
            if dns.servers.is_empty() {
                return Err(config_error("dns.servers must not be empty"));
            }
            let mut servers = HashSet::new();
            for server in &dns.servers {
                validate_dns_server(*server)?;
                if server.is_ipv4() && !has_ipv4_address {
                    return Err(config_error(
                        "an IPv4 DNS server requires an IPv4 interface address",
                    ));
                }
                if server.is_ipv6() && !has_ipv6_address {
                    return Err(config_error(
                        "an IPv6 DNS server requires an IPv6 interface address",
                    ));
                }
                if !servers.insert(*server) {
                    return Err(config_error(format!("duplicate DNS server {server}")));
                }
            }
            let mut search_domains = HashSet::new();
            for domain in &dns.search_domains {
                validate_search_domain(domain)?;
                let canonical = domain
                    .strip_suffix('.')
                    .unwrap_or(domain)
                    .to_ascii_lowercase();
                if !search_domains.insert(canonical) {
                    return Err(config_error(format!(
                        "duplicate DNS search domain {domain}"
                    )));
                }
            }
        }

        if self.is_full_tunnel() {
            let dns = self.dns.as_ref().ok_or_else(|| {
                config_error("a full-tunnel profile must declare a [dns] section")
            })?;
            for server in &dns.servers {
                if !allowed_routes.iter().any(|route| route.contains(*server)) {
                    return Err(config_error(format!(
                        "DNS server {server} is not covered by this profile's allowed_ips"
                    )));
                }
            }
        }

        Ok(self)
    }

    pub fn allowed_routes(&self) -> impl Iterator<Item = IpNetwork> + '_ {
        self.peers
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter().copied())
    }

    #[must_use]
    pub fn dns_priority(&self) -> i32 {
        self.dns
            .as_ref()
            .and_then(|dns| dns.priority)
            .unwrap_or(self.priority)
    }

    #[must_use]
    pub fn is_full_tunnel(&self) -> bool {
        crate::network::covers_family(self.allowed_routes(), false)
            || crate::network::covers_family(self.allowed_routes(), true)
    }
}

fn sanitized_toml_error(error: toml::de::Error) -> AppError {
    let location = error
        .span()
        .map(|span| format!(" at byte {}", span.start))
        .unwrap_or_default();
    // Even message() can contain a supplied string or field name. Only forward
    // diagnostics that exactly match known, value-free messages.
    let detail = match error.message() {
        "key must be canonical base64" => "key must be canonical base64",
        "key must decode to exactly 32 bytes" => "key must decode to exactly 32 bytes",
        "key must use canonical padded base64" => "key must use canonical padded base64",
        message if message.starts_with("unknown field") => "unknown field",
        _ => "invalid syntax or field type",
    };
    AppError::Config(format!("invalid profile TOML{location}: {detail}"))
}

fn validate_metadata(path: &Path, metadata: &fs::Metadata, invoking_uid: u32) -> Result<()> {
    if !metadata.file_type().is_file() {
        return Err(config_error(format!(
            "profile {} must be a regular file",
            path.display()
        )));
    }
    let owner = metadata.uid();
    if owner != 0 && owner != invoking_uid {
        return Err(config_error(format!(
            "profile {} must be owned by root or uid {invoking_uid}",
            path.display()
        )));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(config_error(format!(
            "profile {} is accessible to group or other users (use chmod 600)",
            path.display()
        )));
    }
    if metadata.len() > MAX_PROFILE_BYTES {
        return Err(config_error(format!(
            "profile {} exceeds the 1 MiB limit",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(config_error("name must contain between 1 and 64 bytes"));
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(config_error("name must not be empty"));
    };
    if !first.is_ascii_alphanumeric()
        || !chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(config_error(
            "name must start with an ASCII letter or digit and contain only letters, digits, '.', '-', or '_'",
        ));
    }
    Ok(())
}

fn profile_name_from_path(path: &Path) -> Result<String> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
        return Err(config_error(format!(
            "profile {} must have a .toml filename",
            path.display()
        )));
    }
    let name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| config_error(format!("profile {} has no valid filename", path.display())))?
        .to_owned();
    validate_profile_name(&name)?;
    Ok(name)
}

fn validate_interface_address(network: IpNetwork) -> Result<()> {
    let address = network.ip();
    if address.is_unspecified() || address.is_multicast() || address.is_loopback() {
        return Err(config_error(format!(
            "interface address {network} must be a unicast non-loopback address"
        )));
    }
    Ok(())
}

fn validate_dns_server(server: IpAddr) -> Result<()> {
    let invalid = server.is_unspecified()
        || server.is_multicast()
        || match server {
            IpAddr::V4(address) => address == Ipv4Addr::BROADCAST,
            IpAddr::V6(address) => address == Ipv6Addr::UNSPECIFIED,
        };
    if invalid {
        return Err(config_error(format!("invalid DNS server address {server}")));
    }
    Ok(())
}

pub(crate) fn validate_search_domain(domain: &str) -> Result<()> {
    if domain.trim() != domain || domain.parse::<IpAddr>().is_ok() || !is_valid_dns_name(domain) {
        return Err(config_error("invalid DNS search domain"));
    }
    Ok(())
}

fn split_host_port(value: &str) -> Result<(String, u16)> {
    if value.trim() != value || value.is_empty() {
        return Err(config_error(
            "endpoint must be a non-empty host:port authority",
        ));
    }
    let (raw_host, raw_port) = value
        .rsplit_once(':')
        .ok_or_else(|| config_error("endpoint must include a port"))?;
    let port = u16::from_str(raw_port)
        .map_err(|_| config_error("endpoint port must be between 1 and 65535"))?;
    if port == 0 {
        return Err(config_error("endpoint port must not be zero"));
    }
    let host = if raw_host.starts_with('[') && raw_host.ends_with(']') {
        let inner = &raw_host[1..raw_host.len() - 1];
        inner
            .parse::<Ipv6Addr>()
            .map_err(|_| config_error("invalid bracketed IPv6 endpoint"))?;
        inner.to_owned()
    } else {
        if raw_host.contains(':') {
            return Err(config_error(
                "IPv6 endpoint addresses must be enclosed in brackets",
            ));
        }
        raw_host.to_owned()
    };
    Ok((host, port))
}

fn validate_host(host: &str) -> Result<()> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if !is_valid_dns_name(host) {
        return Err(config_error("endpoint hostname is invalid"));
    }
    Ok(())
}

fn is_valid_dns_name(host: &str) -> bool {
    let without_dot = host.strip_suffix('.').unwrap_or(host);
    if without_dot.is_empty() || without_dot.len() > 253 || !without_dot.is_ascii() {
        return false;
    }
    for label in without_dot.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
    }
    true
}

fn config_error(message: impl Into<String>) -> AppError {
    AppError::Config(message.into())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, fs::symlink},
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::*;

    fn profile_toml(extra: &str) -> String {
        let private = STANDARD.encode([1_u8; 32]);
        let public = STANDARD.encode([2_u8; 32]);
        format!(
            r#"version = 1
priority = 100
{extra}

[interface]
private_key = "{private}"
addresses = ["10.0.0.2/32"]
mtu = 1380

[dns]
servers = ["10.0.0.53"]

[[peers]]
public_key = "{public}"
endpoint = "vpn.example.com:51820"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive = 25
"#
        )
    }

    fn profile_with_preshared_key(key: [u8; 32]) -> String {
        let public_key_line = format!("public_key = \"{}\"", STANDARD.encode([2_u8; 32]));
        profile_toml("").replace(
            &public_key_line,
            &format!(
                "{public_key_line}\npreshared_key = \"{}\"",
                STANDARD.encode(key)
            ),
        )
    }

    #[test]
    fn parses_valid_profile() {
        let profile = Profile::parse(&profile_toml("")).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(profile.name, "work");
        assert!(profile.is_full_tunnel());
    }

    #[test]
    fn dns_priority_defaults_to_routing_priority_and_round_trips() {
        for override_priority in [None, Some(-50), Some(0), Some(200)] {
            let input = match override_priority {
                Some(priority) => {
                    profile_toml("").replace("[dns]", &format!("[dns]\npriority = {priority}"))
                }
                None => profile_toml(""),
            };
            let profile = Profile::parse(&input).unwrap();
            assert_eq!(profile.priority, 100);
            assert_eq!(profile.dns_priority(), override_priority.unwrap_or(100));
            let ipc = serde_json::to_vec(&profile).unwrap();
            let decoded: Profile = serde_json::from_slice(&ipc).unwrap();
            assert_eq!(decoded.dns_priority(), profile.dns_priority());
            let file = toml::to_string(&ProfileFile::from(decoded)).unwrap();
            let reloaded = Profile::parse(&file).unwrap();
            assert_eq!(reloaded.dns.as_ref().unwrap().priority, override_priority);
            assert_eq!(reloaded.dns_priority(), profile.dns_priority());
        }
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = Profile::parse(&profile_toml("surprise = true"))
            .expect_err("unknown field should fail");
        assert!(error.to_string().contains("unknown field"));

        let error = Profile::parse(&profile_toml("name = \"legacy\""))
            .expect_err("embedded profile names should be rejected");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn requires_dns_for_full_tunnel() {
        let input = profile_toml("").replace("[dns]\nservers = [\"10.0.0.53\"]\n\n", "");
        let error = Profile::parse(&input).expect_err("full tunnel without DNS should fail");
        assert!(error.to_string().contains("must declare a [dns]"));
    }

    #[test]
    fn subdivided_defaults_require_dns_and_coverage_in_both_families() {
        for routes in ["0.0.0.0/1\", \"128.0.0.0/1", "::/1\", \"8000::/1"] {
            let input = profile_toml("").replace("0.0.0.0/0", routes);
            let no_dns = input.replace("[dns]\nservers = [\"10.0.0.53\"]\n\n", "");
            assert!(
                Profile::parse(&no_dns)
                    .unwrap_err()
                    .to_string()
                    .contains("must declare a [dns]")
            );
        }
        let input = profile_toml("").replace("0.0.0.0/0", "0.0.0.0/1\", \"128.0.0.0/1");
        assert!(Profile::parse(&input).unwrap().is_full_tunnel());
        let unrouted_dns = input
            .replace("10.0.0.2/32", "10.0.0.2/32\", \"2001:db8::2/128")
            .replace("10.0.0.53", "2001:db8::53");
        assert!(
            Profile::parse(&unrouted_dns)
                .unwrap_err()
                .to_string()
                .contains("not covered")
        );
    }

    #[test]
    fn requires_dns_to_be_routed() {
        let input = profile_toml("")
            .replace(
                "addresses = [\"10.0.0.2/32\"]",
                "addresses = [\"10.0.0.2/32\", \"2001:db8::2/128\"]",
            )
            .replace("10.0.0.53", "2001:db8::53");
        let error = Profile::parse(&input).expect_err("unrouted DNS should fail");
        assert!(error.to_string().contains("not covered"));
    }

    #[test]
    fn parses_and_validates_dns_search_domains() {
        let input = profile_toml("").replace(
            "servers = [\"10.0.0.53\"]",
            "servers = [\"10.0.0.53\"]\nsearch_domains = [\"corp.example.com\", \"dev.example.com.\"]",
        );
        let profile = Profile::parse(&input).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            profile.dns.as_ref().map(|dns| dns
                .search_domains
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()),
            Some(vec!["corp.example.com", "dev.example.com."])
        );

        let duplicate = input.replace("dev.example.com.", "CORP.EXAMPLE.COM.");
        let error = Profile::parse(&duplicate).expect_err("equivalent domains should conflict");
        assert!(error.to_string().contains("duplicate DNS search domain"));

        let invalid = input.replace("dev.example.com.", "not_a_domain");
        let error = Profile::parse(&invalid).expect_err("invalid domain should fail");
        assert!(error.to_string().contains("invalid DNS search domain"));
    }

    #[test]
    fn preshared_key_round_trips_and_debug_output_redacts_secrets() {
        let preshared_key = [3_u8; 32];
        let input = profile_with_preshared_key(preshared_key);
        let profile = Profile::parse(&input).unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{profile:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&STANDARD.encode([1_u8; 32])));
        assert!(!debug.contains(&STANDARD.encode(preshared_key)));
        assert_eq!(
            profile.peers[0]
                .preshared_key
                .as_ref()
                .expect("preshared key should be present")
                .expose(),
            &preshared_key
        );

        let encoded = serde_json::to_vec(&profile)
            .unwrap_or_else(|error| panic!("cannot encode profile for IPC: {error}"));
        let decoded: Profile = serde_json::from_slice(&encoded)
            .unwrap_or_else(|error| panic!("cannot decode profile from IPC: {error}"));
        let decoded = decoded
            .validate()
            .unwrap_or_else(|error| panic!("decoded profile is invalid: {error}"));
        assert_eq!(
            decoded.peers[0]
                .preshared_key
                .as_ref()
                .expect("preshared key should survive IPC")
                .expose(),
            &preshared_key
        );
    }

    #[test]
    fn rejects_all_zero_preshared_key() {
        let input = profile_with_preshared_key([0_u8; 32]);
        let error = Profile::parse(&input).expect_err("an all-zero preshared key should fail");
        let rendered = error.to_string();
        assert!(rendered.contains("preshared_key must not be all zeroes"));
        assert!(!rendered.contains(&STANDARD.encode([0_u8; 32])));
    }

    #[test]
    fn parse_errors_do_not_echo_secret_source_lines() {
        let secret = "this-is-not-a-valid-but-still-sensitive-private-key";
        let input = profile_toml("").replace(&STANDARD.encode([1_u8; 32]), secret);
        let error = Profile::parse(&input).expect_err("invalid key should fail");
        let rendered = error.to_string();
        assert!(rendered.contains("canonical base64"));
        assert!(!rendered.contains(secret));
    }

    #[test]
    fn wrong_type_and_unknown_field_errors_do_not_echo_secret_values() {
        let secret = STANDARD.encode([1_u8; 32]);
        for input in [
            profile_toml("").replace("version = 1", &format!("version = \"{secret}\"")),
            profile_toml(&format!("\"{secret}\" = true")),
            profile_toml("").replace("private_key =", &format!("\"{secret}\" =")),
        ] {
            let error = Profile::parse(&input).expect_err("invalid profile must fail");
            assert!(!error.to_string().contains(&secret));
        }
    }

    #[test]
    fn secure_loader_rejects_open_permissions() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = directory.path().join("profile.toml");
        fs::write(&path, profile_toml("")).unwrap_or_else(|error| panic!("{error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .unwrap_or_else(|error| panic!("{error}"));
        let uid = fs::metadata(&path)
            .unwrap_or_else(|error| panic!("{error}"))
            .uid();
        let error = Profile::load_secure(&path, uid).expect_err("0644 profile should fail");
        assert!(error.to_string().contains("group or other"));
    }

    #[test]
    fn secure_loader_accepts_private_file() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = directory.path().join("profile.toml");
        fs::write(&path, profile_toml("")).unwrap_or_else(|error| panic!("{error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("{error}"));
        let uid = fs::metadata(&path)
            .unwrap_or_else(|error| panic!("{error}"))
            .uid();
        let profile = Profile::load_secure(&path, uid).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(profile.name, "profile");
    }

    #[test]
    fn rejects_invalid_keys_and_interface_addresses() {
        let short_key = STANDARD.encode([7_u8; 16]);
        let invalid_key = profile_toml("").replace(&STANDARD.encode([1_u8; 32]), &short_key);
        assert!(Profile::parse(&invalid_key).is_err());

        let invalid_address = profile_toml("").replace("10.0.0.2/32", "0.0.0.0/32");
        let error = Profile::parse(&invalid_address)
            .expect_err("unspecified interface address should be rejected");
        assert!(error.to_string().contains("unicast"));
    }

    #[test]
    fn accepts_ipv6_allowed_ip_without_an_ipv6_interface_address() {
        let input = profile_toml("").replace(
            "allowed_ips = [\"0.0.0.0/0\"]",
            "allowed_ips = [\"0.0.0.0/0\", \"::/0\"]",
        );
        let profile = Profile::parse(&input).unwrap_or_else(|error| panic!("{error}"));
        assert!(profile.peers[0].allowed_ips.iter().any(IpNetwork::is_ipv6));
    }

    #[test]
    fn equivalent_allowed_ip_prefixes_are_rejected() {
        let input = profile_toml("").replace(
            "allowed_ips = [\"0.0.0.0/0\"]",
            "allowed_ips = [\"10.0.0.0/24\", \"10.0.0.99/24\"]",
        );
        let error = Profile::parse(&input).unwrap_err();
        assert!(error.to_string().contains("occurs more than once"));
    }

    #[test]
    fn allowed_ip_host_bits_are_normalized_without_changing_interface_addresses() {
        let input = profile_toml("").replace("0.0.0.0/0", "10.0.0.99/24");
        let profile = Profile::parse(&input).unwrap();
        assert_eq!(profile.peers[0].allowed_ips[0].to_string(), "10.0.0.0/24");
        assert_eq!(profile.interface.addresses[0].to_string(), "10.0.0.2/32");
    }

    #[test]
    fn secure_loader_rejects_symlinks() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let target = directory.path().join("target.toml");
        let link = directory.path().join("profile.toml");
        fs::write(&target, profile_toml("")).unwrap_or_else(|error| panic!("{error}"));
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("{error}"));
        symlink(&target, &link).unwrap_or_else(|error| panic!("{error}"));
        let uid = fs::metadata(&target)
            .unwrap_or_else(|error| panic!("{error}"))
            .uid();
        let error = Profile::load_secure(&link, uid).expect_err("symlink should be rejected");
        assert!(error.to_string().contains("regular file"));
    }
}
