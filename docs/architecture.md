# Architecture and recovery

[Back to the README](../README.md)

## Supervisor and state

The macOS runtime writes sanitized status data below `/var/run/simplevpn` and a
key-free recovery journal below `/Library/Application Support/SimpleVPN`.
The supervisor does not persist private keys, preshared keys, or full profiles in
either location. Status and recovery data still contain network metadata, such
as profile names, route prefixes, and DNS settings; review them before sharing.
When the supervisor is absent, cached profiles are reported as recovery pending,
never connected, even when the caller cannot read the root-only journal. Cached
routes are no longer reported as installed. Other connection failures and unsafe
or corrupt status files produce a status error.

An exclusive process lock prevents simultaneous supervisors from
recovering or modifying the network. Recovery and status files are read with
ownership, permissions, type, link-count, and size checks. State writes use
exclusive random temporary files and atomic replacement. Unsafe existing state
directories are rejected before their permissions are changed.

## Authorization and app sessions

The control client checks the supervisor's root peer credential before sending
keys. The supervisor authenticates callers through kernel peer credentials and
isolates client I/O in at most 32 concurrent tasks with five-second handshake
read/write deadlines. Network state changes remain serialized.

Only root peers can grant VPN control to a macOS UID. Grants are held in memory
for the supervisor's lifetime and apply to both app and CLI calls from that
account. Authorized accounts can hold app sessions, connect profiles, and
disconnect VPNs. They cannot authorize other accounts or send inline profile
data: they send file paths that the supervisor loads with the authenticated
UID's ownership and permission checks. Root clients may send parsed profiles
after loading them securely. The supervisor validates profiles in both cases;
status needs no authorization.

The two authorization entry points use internal CLI options:

- The app's authorization child uses the macOS prompt to run
  `__authorize-app --invoking-uid <uid>` as root. This starts or reuses the
  supervisor and grants control without changing VPN state. It requires an
  explicit UID and does not need `--authorize-user`.
- CLI `up` and `down` re-execute through `sudo` with `--invoking-uid` for profile
  lookup and ownership checks, plus `--authorize-user` to grant ongoing control.

At launch, the app opens an authenticated `app_session` socket, obtaining a
grant if needed. Startup and simultaneous app actions share session setup. The
socket stays open until the app disconnects or the supervisor shuts down.
Descriptors are closed on exec so child processes cannot prolong the session.

Active tunnels or live app sessions keep the supervisor running. Closing the
last session, including on an app crash, stops an idle supervisor after clean
teardown; active VPNs remain connected. Without app sessions, a successful
last-profile disconnect or `down --all` also exits the supervisor. CLI startup,
failed connections, and pending recovery after app closure retain a 15-second
idle grace period. Grants and status polling never extend that deadline.
Supervisor exit or reboot clears all grants. See the
[lifetime table](configuration.md#authorization-and-supervisor-lifetime) for
user-facing behavior.

Authorization fallback is allowed only after an explicit not-dispatched or
authorization-required result. Operational failures and response timeouts must
not replay an action. If the supervisor dies, the next explicit VPN action
establishes a new session and requests approval if needed; status polling never
prompts.

## Network transitions and recovery

The supervisor journals transitions before mutating the network. A clean stop
restores the captured DNS snapshot, routes, and the prior PF enabled state. Each
privileged write is read back from macOS before the transition is reported as
successful; exact user-managed routes that predate `simplevpn` are rejected
rather than silently replaced. Kernel-cloned endpoint cache routes are safely
reused. A hard crash deliberately leaves the `simplevpn` PF anchors fail-closed;
the next `up` or `down --all` restores the sanitized journal snapshot before
continuing. Cleanup verifies that both project anchors contain no rules or
states and that the root PF rulesets contain no references to them. macOS may
retain an inert, empty anchor name in `pfctl -s Anchors`; that namespace entry
does not affect packet filtering.

An active firewall policy is installed and incompatible states are removed before
routes change. The final firewall policy is removed only after routes and DNS
have been restored successfully; failed restoration retains the guard and the
DNS snapshot for retry. Tunnel and DNS passes use `no state`, so every packet is
checked against the current interface rules. Existing tunnel and DNS states are
evicted when applying a policy: a matching source address alone cannot establish
that a PF state is confined to the tunnel. Endpoint transport exceptions require
root-owned UDP sockets and remain stateful. When an endpoint first becomes
allowed, existing states to it are evicted: PF state records do not establish
the originating socket's UID. Subsequent successful policy applications preserve
transport states for already restricted endpoints. Failed policy applications
and firewall resets discard that trust.
Split-tunnel destinations also receive interface-bound, stateless pass
rules followed by destination blocks, including profiles without DNS. Split-route
passes are checked from longest to shortest prefix. This prevents traffic falling back to
the physical network during route replacement or after a tunnel disappears,
while destinations outside the split routes retain the host's existing policy.
With any full-tunnel profile active, DNS exceptions require a tunnel route;
a resolver outside tunnel coverage is blocked even if a split profile selected
it. This also covers DNS in the opposite IP family from the full-tunnel route.

SimpleVPN verifies that endpoint exception routes have the exact requested prefix
and use either Talpid's current physical default or an OS-recognized physical
network interface. Ethernet and Wi-Fi can share a router, so the kernel-selected
endpoint interface need not match the preferred default interface. Tunnel routes
must still use their exact assigned tunnel. Talpid retains ownership of route
selection and updates.

Physical default-route notifications are coalesced for 250 milliseconds. Failed
refreshes keep the supervisor, tunnels, and firewall alive and retry with backoff
from one second up to 30 seconds. A new network notification advances a pending
retry. Status and disconnect requests remain available between attempts. Profiles
show `reconnecting`, without claiming their routes are installed, until route
verification succeeds. Successful VPN changes cancel outstanding retries;
pending crash recovery remains an explicit recovery operation.
Each refresh reapplies the protected policy atomically and evicts incompatible
states before touching routes. Failure to apply or verify the firewall aborts
that attempt; neither the error path nor the retry timer removes protection.

This follows the separation used by Mullvad: routing determines the path, while
PF enforces which traffic may leave it. The upstream comparison used commit
[`1d3d03df08dd`](https://github.com/mullvad/mullvadvpn-app/tree/1d3d03df08dd0f27fbd98c42acffbffbba4e9e1b).
Its [route manager](https://github.com/mullvad/mullvadvpn-app/blob/1d3d03df08dd0f27fbd98c42acffbffbba4e9e1b/talpid-routing/src/unix/macos/mod.rs)
uses gateways for endpoint routes and handles refresh errors without exiting.
Its [macOS offline monitor](https://github.com/mullvad/mullvadvpn-app/blob/1d3d03df08dd0f27fbd98c42acffbffbba4e9e1b/talpid-core/src/offline/macos.rs)
synthesizes a one-second offline interval during network changes, and its
[PF implementation](https://github.com/mullvad/mullvadvpn-app/blob/1d3d03df08dd0f27fbd98c42acffbffbba4e9e1b/talpid-core/src/firewall/macos.rs)
restricts relay exceptions to root-owned sockets. SimpleVPN retains its live
tunnels during route retries instead of rebuilding Mullvad's tunnel state machine.

## macOS system-command boundary

Routing is managed and independently read back through the vendored
`talpid-routing` `PF_ROUTE` actor; `simplevpn` never invokes the macOS `route(8)`
utility.
The remaining production subprocesses have responsibilities that the pinned
Talpid revision cannot replace without changing behavior or weakening
verification:

- `/sbin/ifconfig` assigns prefix-aware IPv4 and IPv6 addresses, including
  multiple aliases, brings GotaTun interfaces up, and provides independent
  read-back of link state, MTU, addresses, and interface removal. It runs on a
  blocking worker with a ten-second deadline and anonymous output files, so
  completion does not depend on asynchronous child-exit or pipe notifications.
  A timed-out command is killed and reaped before rollback begins.
  `talpid-tunnel` accepts addresses without their CIDR prefixes, does not
  preserve SimpleVPN's multiple-address semantics, and itself invokes
  `ifconfig` for IPv6 on macOS. `talpid-net` only covers MTU access, so using it
  would split interface management without eliminating the subprocess.
- `/sbin/pfctl` is used only for independent read-back of installed rules and
  root anchor references. PF mutations, transactions, state inspection, and
  state removal already use the Rust `pfctl` crate directly through `/dev/pf`.
  Talpid's firewall uses the same crate, has a fixed Mullvad anchor and
  single-tunnel policy model, and exposes no typed rule-inspection API suitable
  for SimpleVPN's concurrent profiles.
- `/usr/bin/sudo` performs interactive privilege bootstrap before the current
  executable replaces itself as root. Talpid expects to run inside an already
  privileged daemon and provides no authorization broker.
- The current SimpleVPN executable starts its private `__supervisor` process
  after elevation. That process lifecycle belongs to SimpleVPN rather than
  Talpid.

The ignored root integration test deliberately invokes `scutil`, `ifconfig`,
and `pfctl`. Those tools provide an independent system-level view of DNS,
interfaces, and PF state instead of validating Talpid or the Rust PF writer
through the same implementation that performed the writes.
