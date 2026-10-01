# Upstream provenance

This directory vendors `talpid-routing` from Mullvad's `mullvadvpn-app` repository.

- Repository: https://github.com/mullvad/mullvadvpn-app.git
- Commit: `c5f20b94b04ebf972f34517ae0cf08e9e82e95cf`
- License: GPL-3.0-or-later (see `LICENSE.md`)

Local changes retained on top of this revision:

- A standalone manifest for SimpleVPN's macOS build, with `talpid-error` pinned
  to the same upstream revision.
- Structured macOS route lookup, exact-route removal, and conditional removal
  of kernel-cloned routes through the route-manager handle.
- Host-route and compact-netmask decoding fixes, explicit kernel lookup error
  handling, and regression tests for these extensions.
- Unaligned route-header reads and bounds checks for declared message lengths
  and socket-address padding, with malformed-input regression tests.
- Formatting with the repository's pinned Rust toolchain.

Upstream's `remove_routes` API is retained alongside the local removal APIs.
SimpleVPN uses its local APIs for acknowledged operations and independent
verification of the routing table.
