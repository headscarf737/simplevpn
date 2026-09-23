// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{AppError, Result};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

pub async fn ifconfig(arguments: &[String]) -> Result<Output> {
    let arguments = arguments.to_vec();
    tokio::task::spawn_blocking(move || {
        tracing::info!(?arguments, "starting ifconfig");
        let result = capture("/sbin/ifconfig", &arguments, COMMAND_TIMEOUT);
        match &result {
            Ok(output) => tracing::info!(status = %output.status, "ifconfig finished"),
            Err(error) => tracing::error!(%error, "ifconfig did not complete"),
        }
        result.map_err(|error| AppError::Platform(format!("cannot execute ifconfig: {error}")))
    })
    .await
    .map_err(|error| AppError::Runtime(format!("ifconfig worker failed: {error}")))?
}

// Poll waitpid on a blocking worker rather than waiting for SIGCHLD and kqueue
// pipe notifications in the supervisor's async task. Anonymous files capture
// output without waiting for EOF on a pipe inherited by another process.
fn capture(program: &str, arguments: &[String], limit: Duration) -> io::Result<Output> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()?;
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            result => {
                // Reap before returning so rollback cannot race a running command.
                let _ = child.kill();
                let _ = child.wait();
                return Err(result.err().unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("{program} exceeded {limit:?}"),
                    )
                }));
            }
        }
    };
    Ok(Output {
        status,
        stdout: read_output(&mut stdout)?,
        stderr: read_output(&mut stderr)?,
    })
}

fn read_output(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(io::Error::other("system command output exceeds 1 MiB"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_both_streams_and_exit_status_without_pipe_capacity_limits() {
        let output = capture(
            "/bin/sh",
            &[
                "-c".into(),
                "head -c 131072 /dev/zero; printf error >&2; exit 7".into(),
            ],
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout.len(), 131_072);
        assert_eq!(output.stderr, b"error");
    }

    #[test]
    fn completion_does_not_wait_for_inherited_output_handles() {
        let started = Instant::now();
        let output = capture(
            "/bin/sh",
            &["-c".into(), "sleep 2 & printf done".into()],
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(output.status.success());
        assert_eq!(output.stdout, b"done");
    }

    #[test]
    fn timed_out_command_is_reaped_before_returning() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("pid");
        let error = capture(
            "/bin/sh",
            &[
                "-c".into(),
                "echo $$ > \"$1\"; exec sleep 10".into(),
                "probe".into(),
                pid_path.to_string_lossy().into_owned(),
            ],
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let pid: libc::pid_t = std::fs::read_to_string(pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: waitpid is queried only for the child whose PID the probe recorded.
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[tokio::test]
    async fn reads_live_loopback_state_without_network_mutation() {
        let output = ifconfig(&["lo0".to_owned()]).await.unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).starts_with("lo0:"));
    }
}
