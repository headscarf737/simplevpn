# macOS menu bar app

[Back to the README](../README.md)

The optional native menu bar app requires Apple Silicon, macOS 13 or later,
and Swift 6 or later (Xcode command-line tools) to build:

```console
./scripts/build-macos-app.sh
open target/macos/SimpleVPN.app
```

The script bundles the release CLI into `SimpleVPN.app` and ad-hoc signs it for
local use. You can move the app to Applications; no separate CLI installation
is needed. This local build is not notarized for distribution.

Click the shield in the macOS menu bar to see profiles from
`~/.config/simplevpn/*.toml`. Click a profile to connect or disconnect it;
multiple profiles can be active together. Checkmarks indicate active profiles,
with standby profiles labeled separately. Profile validation and permissions
are the same as for the CLI. Create or convert profiles using the CLI; the app
does not edit, import, or read profile contents.

A profile stays connected while it owns any route, IPv6 block, or global DNS.
Standby means all its routes and DNS have been superseded by other profiles.

Opening the app starts the supervisor and, if needed, shows the standard macOS
administrator prompt identifying **SimpleVPN** as the requesting app. Approval
lasts for the app's lifetime: connecting, disconnecting, **Disconnect All**, and
reconnecting reuse it. The same account can reuse an already-authorized
supervisor without another prompt, including one started through the CLI.
SimpleVPN stores no password, and authorization is not saved to disk.

The app holds a live socket session. Quitting or crashing closes that session;
the supervisor exits when no apps or VPNs remain. Active VPNs keep running after
quit, and reopening the app reuses their supervisor. If the supervisor itself
stops or the Mac restarts, a new session needs approval again. Cancelling startup
authorization leaves status available; the next explicit VPN action can ask
again. Status refreshes never reopen the prompt.

For CLI-only behavior and session transitions, see
[authorization and supervisor lifetime](configuration.md#authorization-and-supervisor-lifetime).

When upgrading, quit the old app and run `simplevpn down --all` to let its
supervisor exit before opening the updated app. Restarting the Mac also clears
an older supervisor.

Status refreshes without authorization every five seconds, when the menu opens,
and after connection changes. Profiles started through the CLI also appear and
can be disconnected, including when their files are outside the profile
directory or have been removed.

Status requests have a five-second response deadline. An unresponsive supervisor
is reported as unavailable instead of displaying its cached state as current.
The supervisor log records interface-command starts and completions for diagnosis.
The menu app additionally limits its status subprocess to 15 seconds and its
authorization/connection subprocess to 180 seconds (including time for the
administrator prompt). Only an explicit authorization-required result opens the
prompt; other failures and timeouts are not retried as administrator commands.
It monitors child exit independently of the menu run loop and captures output
without waiting for inherited pipe handles to close. A timed-out command is
terminated and reaped, then status is refreshed: a VPN operation already
received by the supervisor may still finish.

**Disconnect All** stops all profiles and can clear pending crash recovery.
**Quit SimpleVPN** closes only the menu bar app and leaves VPN connections
running. When profiles are active, a confirmation dialog warns that they will
remain connected and lets you cancel quitting. The app does not launch
automatically at login.

To build a separate copy while an older app is running, set `SIMPLEVPN_APP_DIR`
to an absolute output path when invoking the build script.

For the app's test command, see [Development](development.md).
