# Development

[Back to the README](../README.md)

## Build

The checked-in toolchain file pins Rust 1.97.1. The first build requires network
access for registry and Git dependencies. `talpid-dns` is fetched from Mullvad
commit `c5f20b94b04ebf972f34517ae0cf08e9e82e95cf`; `talpid-routing` is vendored
from the same revision and patched locally. See
[upstream provenance](../vendor/talpid-routing/UPSTREAM.md).
The remaining routing patches were checked against this revision and are still
needed for exact route verification, recovery and parser robustness; the review
and regression evidence are recorded in that provenance document.

```console
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release --target aarch64-apple-darwin
```

`--workspace` includes the vendored routing crate and its regression tests.
Normal tests do not create VPN connections or modify system networking; the
root integration tests below are ignored unless explicitly selected.

## GitHub Actions builds

The [Build workflow](../.github/workflows/build.yml) runs on pushes and manual
dispatches using an Apple Silicon macOS runner. It uses the pinned
Rust toolchain and lockfile, builds the CLI and menu bar app through
`scripts/build-macos-app.sh`, and checks the CLI help commands and app signature.

Successful runs provide two downloads in the run's **Artifacts** section:

- `simplevpn-macos-arm64.tar.gz`: the standalone CLI, with executable permissions
  preserved. Extract it with `tar -xzf simplevpn-macos-arm64.tar.gz`.
- `SimpleVPN-macos-arm64.zip`: the `SimpleVPN.app` bundle, including its CLI.
  The app is ad-hoc signed and is not notarized.

## Menu bar tests

Run the GUI's tests independently of live VPN connections:

```console
swift test --package-path macos --scratch-path target/macos/swift-debug
```

Socket-pair tests cover app-session authorization, framing, and cleanup in the
normal suite. An additional local-listener test requires permission to bind a
filesystem Unix socket, which restricted execution environments may deny. Run
it outside such an environment (no root or VPN connection required):

```console
SIMPLEVPN_RUN_SOCKET_TESTS=1 swift test --package-path macos \
  --scratch-path target/macos/swift-debug \
  --filter sessionSocketConnectsToLocalListenerWithCloseOnExec
```

See [the menu bar guide](macos-app.md) for building the app bundle.

## Supervisor failure-injection tests

The normal Rust suite exercises the production supervisor through an injectable
network-operation adapter and a controlled clock. It covers firewall application,
read-back verification and state eviction, routes, DNS, journal writes, rollback,
tunnel cleanup and final firewall removal. Tests assert operation ordering,
retained protection, command handling between attempts, partial profile removal,
retry cancellation, dirty startup and status compatibility. Swift tests cover the
new summaries, action availability, legacy responses and discarded cached status
when the supervisor disappears. These tests do not mutate host networking.

Startup tests assert that the connecting policy and journal precede interface
creation, including full coverage assembled from split prefixes, IPv6, DNS and
split-to-full rollback failures. These ordering assertions cover explicit
supervisor commands. Talpid retains upstream automatic route maintenance, which
is outside the fake network adapter's scope.

For a separate app bundle without launching it:

```console
SIMPLEVPN_APP_DIR="$PWD/target/macos/SimpleVPN-Supervisor-Test.app" \
  scripts/build-macos-app.sh
```

Keep automated results separate from the disposable-host packet observations
below. Passing a state-machine test is not evidence of live leak protection.

## Root integration tests

Root integration tests are ignored by default and must be run explicitly on a
disposable macOS test host. They inspect the live interfaces, routing table, DNS
state, PF rules, file permissions, and final restoration. They require two
secure profile paths:

```console
sudo SIMPLEVPN_RUN_ROOT_TESTS=1 \
  SIMPLEVPN_SPLIT_PROFILE=/secure/split.toml \
  SIMPLEVPN_FULL_PROFILE=/secure/full.toml \
  cargo test --locked --test root_macos concurrent_split_and_full_tunnels -- --ignored
```

The private-network/internet scenario has a separate opt-in test. Supply profiles
configured as in the [concurrent-profile example](configuration.md#private-network-and-internet-vpn-together),
with working peers on the disposable test host. Set `SIMPLEVPN_SITE_SUBNET` to
the explicit IPv4 subnet routed by the Site profile, and
`SIMPLEVPN_SITE_SEARCH_DOMAIN` to its configured DNS search domain. Replace the
documentation values below with those of your test network:

```console
sudo SIMPLEVPN_RUN_ROOT_TESTS=1 \
  SIMPLEVPN_SITE_PROFILE=/secure/site.toml \
  SIMPLEVPN_INTERNET_PROFILE=/secure/internet.toml \
  SIMPLEVPN_SITE_SUBNET=192.0.2.0/24 \
  SIMPLEVPN_SITE_SEARCH_DOMAIN=site.example.com \
  cargo test --locked --test root_macos site_and_internet_modes -- --ignored
```

It checks both connection orders, disconnect transitions, route and DNS
ownership, IPv6 blocking, and final restoration. Independently check actual
internet egress and Site-server forwarding with reachable test destinations.

## Reconnect leak validation

The unit tests cover route verification, retries, DNS exception generation, and
PF state eviction, including a switch from split to full tunneling. The root
tests also inspect installed rules for root-only endpoint exceptions and
stateless tunnel/DNS passes. These checks do not prove that the kernel blocks
packets during a real sleep/wake or Ethernet/Wi-Fi transition.

Validate that behavior on a disposable Mac with both links connected, using
controlled IPv4 and IPv6 probe receivers and packet capture outside the Mac on
both physical paths. Send continuous, identifiable TCP and UDP probes, DNS over
UDP and TCP, and HTTPS/QUIC traffic. Confirm that the receivers and captures see
the probes in a control run; a timeout alone is not evidence of blocking.

Repeat while sleeping/waking, unplugging/replugging the dock, losing both links,
and restoring Wi-Fi before Ethernet. Include a sustained route-refresh failure
long enough to reach the 30-second retry interval. Keep existing connections
open and start new ones throughout the transition.

| Traffic | Expected during full-tunnel reconnect |
| --- | --- |
| Application IPv4/IPv6, including sockets bound to either physical interface | Tunnel only, or blocked; no plaintext probe on either physical path |
| Selected DNS server | Allowed only on its assigned tunnel |
| Other DNS servers, including the other IP family | Blocked |
| VPN endpoint IP/UDP port | Root-owned VPN transport is allowed |
| Unprivileged UDP to the VPN endpoint, including a pre-existing PF state | Blocked |
| DHCP and the explicitly allowed NDP messages | Allowed for link recovery |

For split-only profiles, apply the tunnel-only expectation to their configured
destinations; unrelated traffic and explicitly selected external DNS may use
the normal network. Also test enabling a full tunnel after split-only use so
pre-existing endpoint and DNS states cannot bypass the stronger policy.
Capture initial connection as well: after endpoint resolution and connecting
policy verification, protected probes must remain blocked until the tunnel is
usable. Include interface/device startup failures and a failed split-to-full
rollback cleanup; the full guard must remain in place through cleanup. During a
firewall verification failure, confirm that the supervisor issues no route or DNS
commands in that recovery attempt. Talpid and macOS may still change routes;
use the external captures to check that PF continues to constrain protected
traffic during those changes. A verification failure alone establishes neither
successful blocking nor a leak.
After reconnect succeeds, verify that probes resume through the intended VPN.
After an explicit Disconnect All, verify normal connectivity and clean recovery
state.

PF enforcement is also subject to macOS bugs. Mullvad documents
[cases where macOS ignores firewall rules after an OS update](https://github.com/mullvad/mullvadvpn-app/blob/c5f20b94b04ebf972f34517ae0cf08e9e82e95cf/docs/known-issues.md#possible-leaks-on-macos-on-first-start-after-upgrade).
Record the macOS version and whether the machine has rebooted since an update
when reporting results.

## Contributions

Keep changes focused and include a reproducible description of the problem or
feature. For behavior changes, add appropriate tests and run the Rust checks
above; run the Swift tests when changing the menu bar app. Note which checks you
ran and any platform limitations in your pull request.

Keep real VPN profiles outside the checkout, preferably in
`~/.config/simplevpn/`. Use example domains, documentation addresses, and generated
test keys in fixtures. Remove private keys, preshared keys, account details, and
identifying network data before sharing configurations, logs, or issue reports.
The repository's `.gitignore` covers build output, logs, and macOS metadata; it
does not exclude arbitrary profiles or keys. Review staged files before
committing.
