// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    env,
    ffi::{CStr, OsStr, OsString},
    io::Write,
    mem::MaybeUninit,
    os::unix::{ffi::OsStrExt as _, fs::OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use clap::{Parser, Subcommand};

mod config;
mod error;
mod firewall;
mod ipc;
mod journal;
mod network;
mod planner;
#[cfg(target_os = "macos")]
mod platform;
mod secure_fs;
mod status;
mod supervisor;
mod wg_config;

use config::Profile;
use error::{AppError, ExitStatus, Result};
use ipc::{Request, call};

const RUNTIME_DIRECTORY: &str = "/var/run/simplevpn";
const CONTROL_SOCKET: &str = "/var/run/simplevpn/control.sock";
const STATUS_FILE: &str = "/var/run/simplevpn/status.json";
const RECOVERY_JOURNAL: &str = "/Library/Application Support/SimpleVPN/recovery.json";
const USER_CONFIG_DIRECTORY: &str = ".config/simplevpn";

#[derive(Debug, Parser)]
#[command(name = "simplevpn", version, about)]
struct Cli {
    #[arg(long, global = true, hide = true)]
    invoking_uid: Option<u32>,
    #[arg(long, global = true, hide = true)]
    no_elevate: bool,
    #[arg(long, global = true, hide = true, requires = "invoking_uid")]
    authorize_user: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start a profile by name or explicit TOML path.
    Up {
        /// Profile name from ~/.config/simplevpn, or an explicit .toml path.
        profile: PathBuf,
    },
    /// Stop one profile or every profile.
    Down {
        name: Option<String>,
        #[arg(long, conflicts_with = "name")]
        all: bool,
    },
    /// Show supervisor and profile state.
    Status {
        name: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Convert a wg-quick configuration to a simplevpn TOML profile.
    Convert {
        /// WireGuard or wg-quick configuration to convert.
        config: PathBuf,
        /// Write to a new file instead of standard output.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Profile priority.
        #[arg(long, default_value_t = 0)]
        priority: i32,
    },
    #[command(name = "__supervisor", hide = true)]
    Supervisor,
    #[command(name = "__authorize-app", hide = true)]
    AuthorizeApp,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitStatus::Success.into(),
        Err(error) => {
            eprintln!("simplevpn: {error}");
            error.exit_status().into()
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    if cli.authorize_user && effective_uid() != 0 {
        return Err(AppError::AuthorizationRequired);
    }
    match cli.command {
        Commands::AuthorizeApp => {
            let invoking_uid = cli.invoking_uid.ok_or_else(|| {
                AppError::Config("__authorize-app requires --invoking-uid".to_owned())
            })?;
            if effective_uid() != 0 {
                return Err(AppError::AuthorizationRequired);
            }
            ensure_supported_platform()?;
            ensure_supervisor().await?;
            authorize_user(invoking_uid).await
        }
        Commands::Up { profile } => {
            ensure_supported_platform()?;
            if effective_uid() != 0 {
                let path = resolve_profile_path(&profile, effective_uid())?;
                let path = std::path::absolute(path).map_err(|error| {
                    AppError::Config(format!("cannot resolve profile path: {error}"))
                })?;
                return perform_unprivileged(Request::UpFile { path }, cli.no_elevate).await;
            }
            let invoking_uid = cli.invoking_uid.unwrap_or(0);
            let profile_path = resolve_profile_path(&profile, invoking_uid)?;
            let profile = Profile::load_secure(&profile_path, invoking_uid)?;
            ensure_supervisor().await?;
            if cli.authorize_user {
                authorize_user(invoking_uid).await?;
            }
            perform_request(&Request::Up { profile }).await
        }
        Commands::Down { name, all } => {
            ensure_supported_platform()?;
            let request = if all {
                Request::DownAll
            } else if let Some(name) = name {
                Request::Down { name }
            } else {
                return Err(AppError::Config(
                    "down requires a profile name or --all".to_owned(),
                ));
            };
            if effective_uid() != 0 {
                return perform_unprivileged(request, cli.no_elevate).await;
            }
            ensure_supervisor().await?;
            if cli.authorize_user {
                authorize_user(cli.invoking_uid.unwrap_or(0)).await?;
            }
            perform_request(&request).await
        }
        Commands::Status { name, json } => {
            ensure_supported_platform()?;
            show_status(name.as_deref(), json).await
        }
        Commands::Convert {
            config,
            output,
            priority,
        } => {
            let converted = wg_config::convert(&config, priority)?;
            write_converted_profile(output.as_deref(), &converted)
        }
        Commands::Supervisor => {
            ensure_supported_platform()?;
            if effective_uid() != 0 {
                return Err(AppError::Platform(
                    "the supervisor must run as root".to_owned(),
                ));
            }
            #[cfg(target_os = "macos")]
            {
                supervisor::run(
                    Path::new(RUNTIME_DIRECTORY),
                    Path::new(CONTROL_SOCKET),
                    Path::new(STATUS_FILE),
                    Path::new(RECOVERY_JOURNAL),
                )
                .await
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(AppError::Platform("macOS is required".to_owned()))
            }
        }
    }
}

async fn authorize_user(uid: u32) -> Result<()> {
    call(Path::new(CONTROL_SOCKET), &Request::Authorize { uid })
        .await?
        .into_result()?;
    Ok(())
}

async fn perform_unprivileged(request: Request, no_elevate: bool) -> Result<()> {
    match perform_request(&request).await {
        Err(AppError::AuthorizationRequired) if !no_elevate => reexecute_with_sudo(),
        result => result,
    }
}

async fn perform_request(request: &Request) -> Result<()> {
    let (message, _) = call(Path::new(CONTROL_SOCKET), request)
        .await?
        .into_result()?;
    println!("{message}");
    Ok(())
}

fn resolve_profile_path(profile: &Path, invoking_uid: u32) -> Result<PathBuf> {
    if is_explicit_profile_path(profile) {
        return Ok(profile.to_owned());
    }
    profile_path_in_home(profile, &user_home_directory(invoking_uid)?)
}

fn profile_path_in_home(profile: &Path, home: &Path) -> Result<PathBuf> {
    let name = profile
        .to_str()
        .ok_or_else(|| AppError::Config("profile name must be valid UTF-8".to_owned()))?;
    config::validate_profile_name(name)?;
    Ok(home
        .join(USER_CONFIG_DIRECTORY)
        .join(format!("{name}.toml")))
}

fn is_explicit_profile_path(profile: &Path) -> bool {
    profile.extension().and_then(OsStr::to_str) == Some("toml")
        || profile
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty())
}

fn user_home_directory(uid: u32) -> Result<PathBuf> {
    let mut capacity = 16 * 1024;
    loop {
        let mut buffer = vec![0_i8; capacity];
        let mut record = MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: `record`, `buffer`, and `result` are writable for the documented sizes and
        // remain alive until all returned pointers have been copied below.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                record.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut result,
            )
        };
        if status == libc::ERANGE && capacity < 1024 * 1024 {
            capacity *= 2;
            continue;
        }
        if status != 0 {
            return Err(AppError::Platform(format!(
                "cannot resolve home directory for uid {uid}: {}",
                std::io::Error::from_raw_os_error(status)
            )));
        }
        if result.is_null() {
            return Err(AppError::Platform(format!(
                "cannot resolve home directory for uid {uid}"
            )));
        }
        // SAFETY: a successful `getpwuid_r` returned `result` pointing to initialized `record`,
        // whose `pw_dir` field points into the still-live `buffer` and is NUL-terminated.
        let directory = unsafe { CStr::from_ptr((*result).pw_dir) };
        if directory.to_bytes().is_empty() {
            return Err(AppError::Platform(format!(
                "uid {uid} has no home directory"
            )));
        }
        return Ok(PathBuf::from(OsStr::from_bytes(directory.to_bytes())));
    }
}

fn write_converted_profile(path: Option<&Path>, contents: &str) -> Result<()> {
    let mut output: Box<dyn Write> = if let Some(path) = path {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                AppError::Runtime(format!(
                    "cannot create output profile {}: {error}",
                    path.display()
                ))
            })?;
        Box::new(file)
    } else {
        Box::new(std::io::stdout().lock())
    };
    output
        .write_all(contents.as_bytes())
        .map_err(|error| AppError::Runtime(format!("cannot write converted profile: {error}")))?;
    if !contents.ends_with('\n') {
        output.write_all(b"\n").map_err(|error| {
            AppError::Runtime(format!("cannot write converted profile: {error}"))
        })?;
    }
    output
        .flush()
        .map_err(|error| AppError::Runtime(format!("cannot write converted profile: {error}")))
}

async fn show_status(name: Option<&str>, json: bool) -> Result<()> {
    let report = match call(
        Path::new(CONTROL_SOCKET),
        &Request::Status {
            name: name.map(str::to_owned),
        },
    )
    .await
    {
        Ok(response) => response
            .into_result()?
            .1
            .ok_or_else(|| AppError::Ipc("supervisor returned no status".to_owned()))?,
        Err(error @ AppError::StatusUnavailable(_)) => return Err(error),
        Err(_) => {
            let mut report = status::read_if_present(Path::new(STATUS_FILE))?.unwrap_or_default();
            let recovery_pending = journal::JournalStore::new(RECOVERY_JOURNAL)
                .load()
                .map(|journal| journal.is_some_and(|journal| journal.dirty))
                .unwrap_or(report.recovery_pending);
            report.supervisor_unavailable(recovery_pending);
            report.select(name)
        }
    };

    if let Some(name) = name
        && report.profiles.is_empty()
    {
        return Err(AppError::UnknownProfile(name.to_owned()));
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| AppError::Runtime(format!("cannot encode status: {error}")))?
        );
    } else if report.profiles.is_empty() {
        if report.recovery_pending {
            println!("no active profiles; crash recovery is pending");
        } else {
            println!("no active profiles");
        }
    } else {
        for profile in &report.profiles {
            println!(
                "{}: {:?}, priority {}, interface {}, DNS {:?}",
                profile.name, profile.state, profile.priority, profile.interface, profile.dns
            );
            for route in &profile.routes {
                if route.blocked {
                    println!("  {} (blocked: no matching interface address)", route.cidr);
                } else if let Some(owner) = &route.shadowed_by {
                    println!("  {} (shadowed by {owner})", route.cidr);
                } else {
                    println!("  {}", route.cidr);
                }
            }
        }
    }
    Ok(())
}

fn reexecute_with_sudo() -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let validated = Command::new("/usr/bin/sudo")
        .arg("-v")
        .status()
        .map_err(|error| AppError::Platform(format!("cannot execute sudo: {error}")))?;
    if !validated.success() {
        return Err(AppError::Platform(
            "administrator authorization was denied".to_owned(),
        ));
    }
    let executable = env::current_exe()
        .map_err(|error| AppError::Platform(format!("cannot locate simplevpn: {error}")))?;
    let uid = effective_uid();
    let original: Vec<OsString> = env::args_os().skip(1).collect();
    let error = Command::new("/usr/bin/sudo")
        .arg("--")
        .arg(executable)
        .arg("--invoking-uid")
        .arg(uid.to_string())
        .arg("--authorize-user")
        .args(original)
        .exec();
    Err(AppError::Platform(format!("cannot execute sudo: {error}")))
}

async fn ensure_supervisor() -> Result<()> {
    use std::{os::unix::process::CommandExt as _, process::Stdio, time::Duration};

    if tokio::net::UnixStream::connect(CONTROL_SOCKET)
        .await
        .is_ok()
    {
        return Ok(());
    }
    let executable = env::current_exe()
        .map_err(|error| AppError::Platform(format!("cannot locate simplevpn: {error}")))?;
    secure_fs::ensure_directory(Path::new(RUNTIME_DIRECTORY), 0o755)
        .map_err(|error| AppError::Runtime(format!("cannot secure runtime directory: {error}")))?;
    let log_path = Path::new(RUNTIME_DIRECTORY).join("supervisor.log");
    let log = secure_fs::open_log(&log_path).map_err(|error| {
        AppError::Runtime(format!("cannot securely open supervisor log: {error}"))
    })?;
    let stderr = log
        .try_clone()
        .map_err(|error| AppError::Runtime(format!("cannot clone supervisor log: {error}")))?;
    let mut command = Command::new(executable);
    command
        .arg("__supervisor")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));
    // SAFETY: `setsid` is async-signal-safe and the closure performs no allocation.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| AppError::Runtime(format!("cannot launch supervisor: {error}")))?;

    for _ in 0..50 {
        if tokio::net::UnixStream::connect(CONTROL_SOCKET)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(|error| {
            AppError::Runtime(format!("cannot inspect supervisor process: {error}"))
        })? {
            return Err(AppError::Platform(format!(
                "supervisor initialization failed with {status}"
            )));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(AppError::Runtime(
        "supervisor did not become ready within five seconds".to_owned(),
    ))
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions.
    unsafe { libc::geteuid() }
}

fn ensure_supported_platform() -> Result<()> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Err(AppError::Platform(
            "simplevpn requires Apple Silicon macOS".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_profile_names_resolve_below_the_user_config_directory() {
        let path = profile_path_in_home(Path::new("home"), Path::new("/Users/alice"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(path, Path::new("/Users/alice/.config/simplevpn/home.toml"));
    }

    #[test]
    fn explicit_profile_paths_are_preserved() {
        assert!(is_explicit_profile_path(Path::new("home.toml")));
        assert!(is_explicit_profile_path(Path::new("./home")));
        assert!(is_explicit_profile_path(Path::new("/tmp/home.toml")));
        assert!(!is_explicit_profile_path(Path::new("home")));
    }

    #[test]
    fn profile_name_cannot_escape_the_config_directory() {
        assert!(profile_path_in_home(Path::new("../home"), Path::new("/Users/alice")).is_err());
    }

    #[test]
    fn convert_no_longer_accepts_a_name_option() {
        assert!(
            Cli::try_parse_from(["simplevpn", "convert", "wg0.conf", "--name", "home"]).is_err()
        );
    }

    #[test]
    fn remembered_authorization_requires_an_explicit_account() {
        assert!(Cli::try_parse_from(["simplevpn", "--authorize-user", "down", "--all"]).is_err());
        assert!(
            Cli::try_parse_from([
                "simplevpn",
                "--invoking-uid",
                "501",
                "--authorize-user",
                "down",
                "--all"
            ])
            .is_ok()
        );
    }

    #[tokio::test]
    async fn app_authorization_requires_an_explicit_account() {
        let cli = Cli::try_parse_from(["simplevpn", "__authorize-app"]).unwrap();
        assert!(matches!(run(cli).await, Err(AppError::Config(message))
            if message == "__authorize-app requires --invoking-uid"));
    }

    #[tokio::test]
    async fn app_authorization_without_the_optional_flag_still_requires_root() {
        if effective_uid() == 0 {
            return;
        }
        let cli =
            Cli::try_parse_from(["simplevpn", "--invoking-uid", "502", "__authorize-app"]).unwrap();
        assert!(!cli.authorize_user);
        assert!(matches!(
            run(cli).await,
            Err(AppError::AuthorizationRequired)
        ));
    }

    #[tokio::test]
    async fn unprivileged_client_cannot_spoof_authorization_account() {
        if effective_uid() == 0 {
            return;
        }
        let cli = Cli::try_parse_from([
            "simplevpn",
            "--invoking-uid",
            "502",
            "--authorize-user",
            "down",
            "--all",
        ])
        .unwrap();
        assert!(matches!(
            run(cli).await,
            Err(AppError::AuthorizationRequired)
        ));
    }
}
