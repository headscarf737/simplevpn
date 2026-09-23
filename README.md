# SimpleVPN

A WireGuard-compatible VPN client for Apple Silicon macOS, with a command-line
interface and an optional native menu bar app.

SimpleVPN runs multiple VPN profiles together and coordinates their routes, DNS,
and firewall rules. For example, you can keep access to a private network while
sending other traffic through a separate VPN provider.

## Vibe coding disclosure

SimpleVPN was developed with AI coding assistants ("vibe coding"). AI tools were
used to write and revise code and documentation. Passing automated tests does
not guarantee correctness or security; independent code review is welcome.

## Features

- Connect multiple profiles using the GotaTun WireGuard implementation.
- Combine split and full tunnels with explicit route and DNS priorities.
- Import WireGuard and `wg-quick` configurations into TOML profiles.
- Manage connections from the terminal or the macOS menu bar.
- Inspect connection state with human-readable or JSON output.
- Restore network settings on disconnect, with journal-based crash recovery.

## Requirements

- An Apple Silicon Mac. The menu bar app requires macOS 13 or later.
- For source builds: Rust installed through `rustup`; this repository pins Rust **1.97.1**.
- For source builds: Xcode command-line tools; **Swift 6 or later** for the menu bar app.
- A WireGuard configuration from your VPN provider or your own server.
- Administrator access to authorize VPN control.

SimpleVPN is a VPN client; it does not provide VPN servers or accounts.

## Install a GitHub Actions build

You can install a prebuilt Apple Silicon version without Rust, Swift, or Xcode.
Open this repository's **Actions** tab, select **Build**, and open a successful
run. Download the desired package from its **Artifacts** section:

- **Menu bar app:** download `SimpleVPN-macos-arm64.zip`, extract it, and move
  `SimpleVPN.app` to Applications. The app includes its own CLI.
- **Standalone CLI:** download `simplevpn-macos-arm64.tar.gz`, extract it with
  `tar -xzf simplevpn-macos-arm64.tar.gz`, and place the extracted `simplevpn`
  executable in a directory on your `PATH`.

The app is ad-hoc signed and is not notarized. See
[GitHub Actions builds](docs/development.md#github-actions-builds) for workflow
details, then follow the [quick start](#quick-start) to configure a profile.

## Install from source

From a checkout of this repository, install the CLI:

```console
cargo install --path . --locked --target aarch64-apple-darwin
simplevpn --help
```

Cargo installs the executable into `~/.cargo/bin` by default. Ensure that
directory is on your `PATH`. The first build needs network access to download
dependencies.

To build and open the optional menu bar app:

```console
./scripts/build-macos-app.sh
open target/macos/SimpleVPN.app
```

The app bundles its own CLI and can be moved to Applications. It is ad-hoc signed
for local use and is not notarized. See the [menu bar guide](docs/macos-app.md)
for details.

## Quick start

Create a private profile directory, then convert an existing WireGuard
configuration. Replace `/path/to/wg0.conf` with your configuration's path:

```console
mkdir -p "$HOME/.config/simplevpn"
chmod 700 "$HOME/.config/simplevpn"
simplevpn convert /path/to/wg0.conf --priority 100 \
  --output "$HOME/.config/simplevpn/work.toml"
simplevpn up work
simplevpn status
```

The converter creates a new file with mode `0600` and refuses to overwrite an
existing file. Unsupported settings, including `wg-quick` hooks and route-table
overrides, produce an error. Keep profiles private: they contain your VPN keys.

The filename determines the profile name: `work.toml` becomes `work`. Profiles
in `~/.config/simplevpn` also appear in the menu bar app. The CLI uses `sudo`
for initial administrator approval; the app uses the macOS prompt. Both reuse
approval for the same account while the supervisor runs. Status checks never
elevate. See [authorization and supervisor lifetime](docs/configuration.md#authorization-and-supervisor-lifetime)
for reconnect and quit behavior.

```console
simplevpn status work --json
simplevpn down work
simplevpn down --all
```

To connect another profile, run `simplevpn up` with its name. Give profiles
different priorities when they compete for the same routes or global DNS.
See [configuration and concurrent profiles](docs/configuration.md) for the
schema, ownership rules, and a complete example.

## Connection behavior

Quitting the menu bar app leaves VPN connections running. Use **Disconnect All**
or `simplevpn down --all` to stop them. The app does not start automatically at
login.

An unreachable peer does not trigger automatic failover. After a supervisor
crash, firewall rules intentionally remain in place and may block traffic. Run
`simplevpn down --all` to recover the saved network state, or `simplevpn up`
with a profile to recover before connecting. See [architecture and
recovery](docs/architecture.md) for the details.

## Documentation and contributing

- [Configuration and CLI reference](docs/configuration.md)
- [macOS menu bar app](docs/macos-app.md)
- [Architecture and recovery](docs/architecture.md)
- [Development, testing, and contributions](docs/development.md)

Bug reports and pull requests are welcome. Include reproduction steps and the
relevant macOS version, and remove keys and identifying network details from
anything you share.

## License

SimpleVPN is licensed under [GPL-3.0-or-later](LICENSE). It uses GotaTun and
Mullvad's Talpid components; the vendored routing code retains its
[upstream provenance](vendor/talpid-routing/UPSTREAM.md) and
[license](vendor/talpid-routing/LICENSE.md).
