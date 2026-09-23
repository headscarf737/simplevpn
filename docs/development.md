# Development

[Back to the README](../README.md)

## Build

The checked-in toolchain file pins Rust 1.97.1. The first build requires network
access for registry and Git dependencies. `talpid-dns` is fetched from Mullvad
commit `16c2f486e79d0579225b65b55e57fb1f9c8df7a2`; `talpid-routing` is vendored
from the same revision and patched locally. See
[upstream provenance](../vendor/talpid-routing/UPSTREAM.md).

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
