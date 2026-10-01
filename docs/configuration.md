# Configuration and CLI reference

[Back to the README](../README.md)

```console
simplevpn up work
simplevpn down work
simplevpn down --all
simplevpn status [work] [--json]
simplevpn convert wg0.conf [--priority 100] [-o ~/.config/simplevpn/work.toml]
```

## Profile lookup

`up work` loads `~/.config/simplevpn/work.toml` from the invoking user's home
directory. An explicit `.toml` path is also supported. The filename stem is the
profile name used by `up`, `down`, and `status`; profile files do not contain a
separate `name` field. Names must be 1–64 ASCII characters, start with a letter
or digit, and contain only letters, digits, `.`, `-`, or `_`.

Profiles must be regular files owned by root or the invoking user, with no group
or other permissions (use `chmod 600`). Symbolic links are rejected. Profile
files and WireGuard conversion inputs are limited to 1 MiB.

## Authorization and supervisor lifetime

`up` and `down` reuse authorization for your macOS account in the running
supervisor; otherwise they re-execute through `sudo` and authorize that account.
`status` is read-only and never elevates. The menu bar app uses the standard
macOS administrator prompt and shares authorization with CLI calls from the
same account.

| Event | Supervisor and authorization |
| ----- | ---------------------------- |
| Disconnect the last VPN with no app open | The supervisor exits; the next connection needs approval. |
| Disconnect all VPNs with an app open | The app session keeps the supervisor and approval available for reconnecting. |
| Quit the last app with VPNs active | VPNs stay connected; reopening the app reuses approval. |
| Quit the last app with no VPNs active | The idle supervisor exits. Pending crash recovery retains a short grace period. |
| Supervisor exits or the Mac restarts | In-memory authorization is cleared. |

Approval is account-specific and is never saved to disk. See
[architecture](architecture.md#authorization-and-app-sessions) for protocol and
recovery details.

## Profile format

Profiles use a strict, versioned schema; unknown fields are errors. The keys below
are placeholders and must be replaced before use:

```toml
version = 1
priority = 100

[interface]
private_key = "<base64-encoded 32-byte key>"
addresses = ["10.0.0.2/32", "fd00::2/128"]
mtu = 1380

[dns]
servers = ["10.0.0.53"]
search_domains = ["corp.example.com"]

[[peers]]
public_key = "<base64-encoded 32-byte key>"
preshared_key = "<optional base64-encoded 32-byte key>"
endpoint = "vpn.example.com:51820"
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive = 25
```

`version` must be `1`, and top-level `priority` is a required signed 32-bit
integer. At least one interface address and one peer are required. Each peer
must have a unique public key, an endpoint, and a non-empty `allowed_ips` list.
An endpoint is a hostname or IP address with a port; bracket IPv6 addresses,
for example `[2001:db8::1]:51820`.

| Optional field | Behavior when omitted | Constraints when set |
| -------------- | --------------------- | -------------------- |
| `interface.mtu` | Leaves the tunnel's default MTU unchanged | `576`–`9000`; at least `1280` with an IPv6 interface address |
| `interface.listen_port` | Chooses a port automatically | `1`–`65535` |
| `dns` | Does not request global DNS ownership | Required for full tunnels; `servers` must be non-empty |
| `dns.priority` | Uses top-level `priority` | Signed 32-bit integer |
| `dns.search_domains` | No search domains | Valid DNS names without duplicates |
| `peers[].preshared_key` | No preshared key | The remote peer must use the same key |
| `peers[].persistent_keepalive` | Keepalive disabled | `1`–`65535` seconds |

All keys must be non-zero 32-byte values in canonical padded base64. Omit
`preshared_key` if your configuration does not use it. DNS servers require a
matching interface address family. An IPv4 `allowed_ips` entry also requires an
IPv4 interface address. IPv6 `allowed_ips` entries are accepted on an IPv4-only
interface, but those CIDRs are blocked by PF instead of routed into the tunnel;
`::/0` therefore blocks IPv6.

Full-tunnel detection includes equivalent sets of smaller prefixes, such as
`0.0.0.0/1` plus `128.0.0.0/1`. Such profiles require DNS just like `/0`
profiles. The firewall also enables full lockdown when active profiles together
cover an entire address family.
While full lockdown is active, the selected DNS servers must have tunnel routes.
A split profile may select an external resolver, but that resolver is blocked
if no active tunnel covers it. This prevents DNS from bypassing full lockdown
through the other IP family.

Split tunnels also protect their configured destinations with firewall rules,
even without a DNS section. Traffic to those destinations is blocked if it would
leave through an interface other than the selected tunnel; unrelated traffic
keeps using the host's existing policy. VPN endpoint and network-maintenance
exceptions still apply.

## Converting WireGuard configurations

`convert` reads a WireGuard or `wg-quick` configuration and emits an equivalent
profile to standard output. Its priority defaults to `0`; use `--priority` to
override it. `--output` creates a new mode-`0600` file and refuses to overwrite
an existing file. The output filename becomes the profile name when loaded.
Settings with no SimpleVPN equivalent, including route tables and up/down hooks,
are rejected rather than silently discarded. Non-IP entries in a WireGuard
`DNS` setting are converted to `search_domains`.

## Route and DNS ownership

Higher profile priorities own identical CIDRs. Global DNS uses `[dns].priority`,
an optional signed integer that defaults to the profile priority. Equal-priority
ownership conflicts reject the new profile: route conflicts compare profile
priorities, while DNS conflicts compare effective DNS priorities independently.
Allowed IPs are normalized to network prefixes
before duplicate and priority checks. Different CIDRs coexist and macOS applies
longest-prefix matching. Full-tunnel profiles require DNS, and their declared
DNS servers must be covered by that profile's allowed IPs. With concurrent
profiles, DNS configuration comes from the selected global DNS owner while each
server follows the aggregate longest-prefix route, or the physical default when
no tunnel route covers it. Search domains follow the selected global DNS owner.

## Private network and internet VPN together

In this example, **Site** connects to a private network, and **Internet** connects
to a separate VPN provider. Give Site lower routing priority and higher DNS
priority than Internet. Keep an explicit Site subnet alongside Site's default
routes so longest-prefix routing continues to send Site destinations there when
Internet owns the defaults:

| Profile  | Top-level `priority` | `[dns].priority` | Peer `allowed_ips`                  | DNS server      |
| -------- | -------------------- | ---------------- | ----------------------------------- | --------------- |
| Site     | `100`                | `200`            | `192.0.2.0/24`, `0.0.0.0/0`, `::/0` | `192.0.2.53`    |
| Internet | `200`                | `100`            | `0.0.0.0/0`, `::/0`                 | `198.51.100.53` |

These addresses and domains are documentation examples. Replace them with your
actual subnet, DNS servers, keys, and endpoints. The Site profile can use a DNS
search domain such as `site.example.com`. With an IPv4-only Site interface and a
dual-stack Internet interface, these settings produce:

| Active profiles | Site subnet | Other IPv4 | IPv6     | System DNS |
| --------------- | ----------- | ---------- | -------- | ---------- |
| Site            | Site        | Site       | Blocked  | Site       |
| Site + Internet | Site        | Internet   | Internet | Site       |
| Internet        | Internet    | Internet   | Internet | Internet   |

The Site VPN server must forward/NAT internet-bound IPv4 traffic. Connection
order does not matter; disconnecting either profile transfers ownership to the
remaining profile. An unreachable tunnel does not trigger automatic failover.
DNS settings govern the system resolver and standard DNS traffic, not an
application's own encrypted DNS implementation. Both profiles are managed by
SimpleVPN; a separate provider app is not needed for these connections.

When upgrading, quit the menu bar app and run `simplevpn down --all` so the old
supervisor exits before using new profile fields. Preserve mode `0600` when
editing profiles or keeping backups.

## Exit statuses

Exit statuses are `0` success, `1` runtime failure, `2` invalid usage/config,
`3` unknown or inactive profile, `4` unsupported platform or privilege failure,
and `5` administrator authorization required (used by the app's noninteractive
control calls).
