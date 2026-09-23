// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    collections::HashSet,
    io,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    sync::{mpsc, oneshot, watch},
    time::timeout,
};
use zeroize::Zeroizing;

use crate::{AppError, ExitStatus, Result, config::Profile, status::StatusReport};

const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub struct PendingRequest {
    pub peer_uid: u32,
    pub request: Request,
    pub response: oneshot::Sender<Response>,
}

// Grants live only in this supervisor. Only an already-elevated client can
// authorize a macOS account; subsequent calls use kernel peer credentials.
#[derive(Default)]
pub struct ControlAccess {
    users: RwLock<HashSet<u32>>,
}

impl ControlAccess {
    pub fn authorize(&self, peer_uid: u32, uid: u32) -> Result<()> {
        if peer_uid != 0 {
            return Err(AppError::AuthorizationRequired);
        }
        if uid != 0 {
            self.users
                .write()
                .expect("control access lock poisoned")
                .insert(uid);
        }
        Ok(())
    }

    pub fn check(&self, peer_uid: u32, request: &Request) -> Result<()> {
        if peer_uid == 0 || matches!(request, Request::Status { .. }) {
            return Ok(());
        }
        // Inline profile data remains root-only. Account-authorized clients must load
        // files through the supervisor's ownership and permission checks.
        if matches!(
            request,
            Request::UpFile { .. } | Request::Down { .. } | Request::DownAll | Request::AppSession
        ) && self
            .users
            .read()
            .expect("control access lock poisoned")
            .contains(&peer_uid)
        {
            return Ok(());
        }
        Err(AppError::AuthorizationRequired)
    }
}

// A lease belongs to a live, authenticated socket, not to an account grant.
// Dropping the socket (including app crashes) releases it automatically.
pub struct AppSessions {
    count: watch::Sender<usize>,
    shutdown: watch::Sender<bool>,
}

impl Default for AppSessions {
    fn default() -> Self {
        Self {
            count: watch::channel(0).0,
            shutdown: watch::channel(false).0,
        }
    }
}

impl AppSessions {
    pub fn subscribe(&self) -> watch::Receiver<usize> {
        self.count.subscribe()
    }

    pub fn active(&self) -> bool {
        *self.count.borrow() > 0
    }

    pub fn stop(&self) {
        self.shutdown.send_replace(true);
    }

    fn acquire(&self) -> AppSessionLease<'_> {
        self.count.send_modify(|count| *count += 1);
        AppSessionLease(self)
    }

    async fn hold(&self, stream: &mut UnixStream) {
        let mut shutdown = self.shutdown.subscribe();
        if *shutdown.borrow_and_update() {
            return;
        }
        // This socket carries only a lease after the handshake. EOF, an I/O
        // error, or unexpected additional data all end that lease.
        let mut byte = [0];
        tokio::select! {
            _ = stream.read(&mut byte) => {},
            _ = shutdown.changed() => {},
        }
    }
}

struct AppSessionLease<'a>(&'a AppSessions);

impl Drop for AppSessionLease<'_> {
    fn drop(&mut self) {
        self.0.count.send_modify(|count| *count -= 1);
    }
}

// Client I/O runs separately from privileged state transitions. Disconnects,
// malformed requests, and backpressure must never terminate the supervisor.
pub async fn serve_connection(
    mut stream: UnixStream,
    requests: mpsc::Sender<PendingRequest>,
    access: Arc<ControlAccess>,
    sessions: Arc<AppSessions>,
) {
    let Ok(uid) = peer_uid(&stream) else {
        return;
    };
    let mut session = None;
    let response = match timeout(IO_TIMEOUT, read_frame::<Request, _>(&mut stream)).await {
        Ok(Ok(request)) => {
            if let Err(error) = access.check(uid, &request) {
                let _ = timeout(
                    IO_TIMEOUT,
                    write_frame(&mut stream, &Response::from_error(&error)),
                )
                .await;
                return;
            }
            if matches!(request, Request::AppSession) {
                session = Some(sessions.acquire());
            }
            let (response, receiver) = oneshot::channel();
            if requests
                .send(PendingRequest {
                    peer_uid: uid,
                    request,
                    response,
                })
                .await
                .is_err()
            {
                return;
            }
            let Ok(response) = receiver.await else {
                return;
            };
            response
        }
        Ok(Err(error)) => Response::from_error(&error),
        Err(_) => return,
    };
    let written = timeout(IO_TIMEOUT, write_frame(&mut stream, &response)).await;
    if session.is_some() && matches!(response, Response::Ok { .. }) && matches!(written, Ok(Ok(())))
    {
        sessions.hold(&mut stream).await;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    Up { profile: Profile },
    UpFile { path: PathBuf },
    Down { name: String },
    DownAll,
    Authorize { uid: u32 },
    AppSession,
    Status { name: Option<String> },
}

impl Request {
    #[must_use]
    pub const fn changes_vpn(&self) -> bool {
        matches!(
            self,
            Self::Up { .. } | Self::UpFile { .. } | Self::Down { .. } | Self::DownAll
        )
    }

    #[must_use]
    pub const fn mutates_state(&self) -> bool {
        !matches!(self, Self::Status { .. })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<StatusReport>,
    },
    Error {
        exit_status: u8,
        message: String,
    },
}

impl Response {
    #[must_use]
    pub fn from_error(error: &AppError) -> Self {
        Self::Error {
            exit_status: error.exit_status() as u8,
            message: match error {
                AppError::UnknownProfile(name) => name.clone(),
                _ => error.to_string(),
            },
        }
    }

    pub fn into_result(self) -> Result<(String, Option<StatusReport>)> {
        match self {
            Self::Ok { message, status } => Ok((message, status)),
            Self::Error {
                exit_status,
                message,
            } => Err(match exit_status {
                value if value == ExitStatus::Invalid as u8 => AppError::Config(message),
                value if value == ExitStatus::UnknownProfile as u8 => {
                    AppError::UnknownProfile(message)
                }
                value if value == ExitStatus::Platform as u8 => AppError::Platform(message),
                value if value == ExitStatus::AuthorizationRequired as u8 => {
                    AppError::AuthorizationRequired
                }
                _ => AppError::Runtime(message),
            }),
        }
    }
}

pub async fn call(socket: &Path, request: &Request) -> Result<Response> {
    let stream = timeout(IO_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| connection_error(io::Error::from(io::ErrorKind::TimedOut), request))?
        .map_err(|error| connection_error(error, request))?;
    let result = call_authenticated(stream, request).await;
    if matches!(request, Request::Status { .. }) {
        // Do not present cached state when a reachable supervisor stops responding.
        result.map_err(|error| AppError::StatusUnavailable(error.to_string()))
    } else {
        result
    }
}

fn connection_error(error: io::Error, request: &Request) -> AppError {
    // Only a definite failure before dispatch can trigger authorization/retry.
    // Never retry an operation after a write or response timeout.
    let absent = matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    );
    if request.mutates_state() && absent {
        AppError::AuthorizationRequired
    } else if !request.mutates_state() && !absent {
        AppError::StatusUnavailable(format!("cannot contact supervisor: {error}"))
    } else {
        AppError::Ipc(format!("cannot contact supervisor: {error}"))
    }
}

async fn call_authenticated(mut stream: UnixStream, request: &Request) -> Result<Response> {
    // Authenticate the server before sending a profile containing secret keys.
    let uid = peer_uid(&stream)
        .map_err(|_| AppError::Ipc("cannot authenticate supervisor".to_owned()))?;
    if uid != 0 {
        return Err(AppError::Ipc("supervisor must be owned by root".to_owned()));
    }
    timeout(IO_TIMEOUT, write_frame(&mut stream, request))
        .await
        .map_err(|_| AppError::Ipc("timed out sending IPC request".to_owned()))??;
    read_response(&mut stream, request).await
}

async fn read_response<R: AsyncRead + Unpin>(
    reader: &mut R,
    request: &Request,
) -> Result<Response> {
    let limit = if request.mutates_state() {
        Duration::from_secs(120)
    } else {
        IO_TIMEOUT
    };
    timeout(limit, read_frame(reader))
        .await
        .map_err(|_| {
            AppError::Ipc(
                if request.mutates_state() {
                    "timed out awaiting supervisor; the operation may still be running"
                } else {
                    "supervisor is not responding to status requests; a network change may still be running"
                }.to_owned(),
            )
        })?
}

pub async fn read_frame<T, R>(reader: &mut R) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncRead + Unpin,
{
    let length = reader
        .read_u32()
        .await
        .map_err(|error| AppError::Ipc(format!("cannot read IPC frame: {error}")))?
        as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(AppError::Ipc(format!("invalid IPC frame length {length}")));
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|error| AppError::Ipc(format!("cannot read IPC payload: {error}")))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        // Serde diagnostics may include the value that failed validation.
        AppError::Ipc(format!(
            "cannot decode IPC payload at line {}, column {}",
            error.line(),
            error.column()
        ))
    })
}

pub async fn write_frame<T, W>(writer: &mut W, value: &T) -> Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let bytes = Zeroizing::new(
        serde_json::to_vec(value)
            .map_err(|_| AppError::Ipc("cannot encode IPC payload".to_owned()))?,
    );
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(AppError::Ipc("IPC payload is too large".to_owned()));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| AppError::Ipc("IPC payload is too large".to_owned()))?;
    writer
        .write_u32(length)
        .await
        .map_err(|error| AppError::Ipc(format!("cannot write IPC frame: {error}")))?;
    writer
        .write_all(&bytes)
        .await
        .map_err(|error| AppError::Ipc(format!("cannot write IPC payload: {error}")))?;
    writer
        .flush()
        .await
        .map_err(|error| AppError::Ipc(format!("cannot flush IPC payload: {error}")))
}

#[cfg(target_os = "macos")]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn getpeereid(
            socket: libc::c_int,
            euid: *mut libc::uid_t,
            egid: *mut libc::gid_t,
        ) -> libc::c_int;
    }

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `stream` owns a valid connected Unix socket and both output pointers are valid.
    let result = unsafe { getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) };
    if result == 0 {
        Ok(uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
pub fn peer_uid(_stream: &UnixStream) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credentials require macOS",
    ))
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    #[test]
    fn only_root_can_grant_control_and_grants_are_account_scoped() {
        let access = ControlAccess::default();
        assert!(access.check(501, &Request::Status { name: None }).is_ok());
        assert!(access.check(501, &Request::DownAll).is_err());
        assert!(access.authorize(501, 501).is_err());
        access.authorize(0, 501).unwrap();
        for request in [
            Request::UpFile {
                path: PathBuf::from("/Users/alice/work.toml"),
            },
            Request::Down {
                name: "work".to_owned(),
            },
            Request::DownAll,
            Request::AppSession,
        ] {
            assert!(access.check(501, &request).is_ok());
            assert!(access.check(502, &request).is_err());
            assert!(access.check(0, &request).is_ok());
        }
        assert!(access.check(501, &Request::Authorize { uid: 502 }).is_err());
        assert!(access.authorize(501, 502).is_err());
        assert!(access.check(502, &Request::DownAll).is_err());
        // A new supervisor always starts without remembered account access.
        assert!(
            ControlAccess::default()
                .check(501, &Request::DownAll)
                .is_err()
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn app_sessions_follow_live_sockets_and_do_not_block_shutdown() {
        let uid = crate::effective_uid();
        let access = Arc::new(ControlAccess::default());
        access.authorize(0, uid).unwrap();
        let sessions = Arc::new(AppSessions::default());
        let (tx, mut rx) = mpsc::channel(2);
        let mut clients = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let (mut client, server) = UnixStream::pair().unwrap();
            tasks.push(tokio::spawn(serve_connection(
                server,
                tx.clone(),
                access.clone(),
                sessions.clone(),
            )));
            write_frame(&mut client, &Request::AppSession)
                .await
                .unwrap();
            let pending = timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(sessions.active(), "lease must exist before dispatch");
            pending
                .response
                .send(Response::Ok {
                    message: String::new(),
                    status: None,
                })
                .unwrap();
            assert!(matches!(
                read_frame::<Response, _>(&mut client).await.unwrap(),
                Response::Ok { .. }
            ));
            clients.push(client);
        }
        // A dropped socket models normal quit and process death equally.
        drop(clients.pop());
        timeout(Duration::from_secs(1), tasks.pop().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(sessions.active(), "the other app is still running");
        sessions.stop();
        timeout(Duration::from_secs(1), tasks.pop().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(!sessions.active());
        assert_eq!(clients[0].read(&mut [0]).await.unwrap(), 0);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn unauthorized_app_cannot_hold_a_supervisor_session() {
        if crate::effective_uid() == 0 {
            return;
        }
        let (mut client, server) = UnixStream::pair().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let sessions = Arc::new(AppSessions::default());
        let task = tokio::spawn(serve_connection(
            server,
            tx,
            Arc::default(),
            sessions.clone(),
        ));
        write_frame(&mut client, &Request::AppSession)
            .await
            .unwrap();
        assert!(matches!(
            read_frame::<Response, _>(&mut client).await.unwrap(),
            Response::Error { exit_status: 5, .. }
        ));
        task.await.unwrap();
        assert!(!sessions.active());
        assert!(rx.recv().await.is_none());
    }

    #[test]
    fn authorization_retry_is_only_allowed_before_dispatch() {
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::ConnectionRefused] {
            assert!(matches!(
                connection_error(io::Error::from(kind), &Request::DownAll),
                AppError::AuthorizationRequired
            ));
        }
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionReset,
        ] {
            assert!(matches!(
                connection_error(io::Error::from(kind), &Request::DownAll),
                AppError::Ipc(_)
            ));
        }
        assert!(matches!(
            connection_error(
                io::Error::from(io::ErrorKind::NotFound),
                &Request::Status { name: None }
            ),
            AppError::Ipc(_)
        ));
        assert!(matches!(
            Response::from_error(&AppError::AuthorizationRequired).into_result(),
            Err(AppError::AuthorizationRequired)
        ));
    }

    #[test]
    fn status_cache_is_only_allowed_when_the_supervisor_is_definitely_absent() {
        let request = Request::Status { name: None };
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::ConnectionRefused] {
            assert!(matches!(
                connection_error(io::Error::from(kind), &request),
                AppError::Ipc(_)
            ));
        }
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionReset,
        ] {
            assert!(matches!(
                connection_error(io::Error::from(kind), &request),
                AppError::StatusUnavailable(_)
            ));
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn authorized_account_can_reuse_control_over_multiple_connections() {
        let uid = crate::effective_uid();
        if uid == 0 {
            return;
        }
        let access = Arc::new(ControlAccess::default());
        access.authorize(0, uid).unwrap();
        for request in [
            Request::DownAll,
            Request::UpFile {
                path: PathBuf::from("/Users/example/work.toml"),
            },
            Request::Down {
                name: "work".to_owned(),
            },
        ] {
            let (mut client, server) = UnixStream::pair().unwrap();
            let (tx, mut rx) = mpsc::channel(1);
            let task = tokio::spawn(serve_connection(server, tx, access.clone(), Arc::default()));
            write_frame(&mut client, &request).await.unwrap();
            let pending = timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(pending.peer_uid, uid);
            pending
                .response
                .send(Response::Ok {
                    message: String::new(),
                    status: None,
                })
                .unwrap();
            assert!(matches!(
                read_frame::<Response, _>(&mut client).await.unwrap(),
                Response::Ok { .. }
            ));
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn stalled_status_reply_has_a_short_deadline() {
        let (_server, mut client) = duplex(4096);
        let started = tokio::time::Instant::now();
        let error = timeout(
            IO_TIMEOUT + Duration::from_secs(1),
            read_response(&mut client, &Request::Status { name: None }),
        )
        .await
        .expect("status must not use the two-minute mutation deadline")
        .expect_err("a silent supervisor must not look disconnected");
        assert!(started.elapsed() >= IO_TIMEOUT);
        assert!(error.to_string().contains("not responding to status"));
    }

    #[tokio::test]
    async fn status_reply_is_returned_as_soon_as_it_arrives() {
        let (mut server, mut client) = duplex(4096);
        let response = Response::Ok {
            message: "ready".to_owned(),
            status: None,
        };
        write_frame(&mut server, &response).await.unwrap();
        let result = timeout(
            Duration::from_secs(1),
            read_response(&mut client, &Request::Status { name: None }),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(result, Response::Ok { message, .. } if message == "ready"));
    }

    #[tokio::test]
    async fn frames_round_trip() {
        let (mut writer, mut reader) = duplex(4096);
        let request = Request::Status {
            name: Some("work".to_owned()),
        };
        write_frame(&mut writer, &request)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decoded: Request = read_frame(&mut reader)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(decoded, Request::Status { name: Some(name) } if name == "work"));
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocation() {
        let (mut writer, mut reader) = duplex(16);
        writer
            .write_u32((MAX_FRAME_BYTES + 1) as u32)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let result: Result<Request> = read_frame(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn malformed_payload_does_not_echo_sensitive_values() {
        let (mut writer, mut reader) = duplex(4096);
        let sensitive = "sensitive-profile-key";
        write_frame(&mut writer, &serde_json::json!({"command": sensitive}))
            .await
            .unwrap();
        let error = read_frame::<Request, _>(&mut reader).await.unwrap_err();
        assert!(!error.to_string().contains(sensitive));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn disconnected_client_does_not_fail_the_server_task() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(serve_connection(server, tx, Arc::default(), Arc::default()));
        write_frame(&mut client, &Request::Status { name: None })
            .await
            .unwrap();
        let pending = rx.recv().await.unwrap();
        drop(client);
        pending
            .response
            .send(Response::Ok {
                message: String::new(),
                status: None,
            })
            .unwrap();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn slow_client_does_not_block_another_request() {
        let (_idle, idle_server) = UnixStream::pair().unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let (tx, mut rx) = mpsc::channel(2);
        let idle_task = tokio::spawn(serve_connection(
            idle_server,
            tx.clone(),
            Arc::default(),
            Arc::default(),
        ));
        let task = tokio::spawn(serve_connection(server, tx, Arc::default(), Arc::default()));
        write_frame(&mut client, &Request::Status { name: None })
            .await
            .unwrap();
        let pending = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        pending
            .response
            .send(Response::Ok {
                message: String::new(),
                status: None,
            })
            .unwrap();
        let response: Response = timeout(Duration::from_secs(1), read_frame(&mut client))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(response, Response::Ok { .. }));
        task.await.unwrap();
        idle_task.abort();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn client_that_stops_reading_is_disconnected_at_the_write_deadline() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(serve_connection(server, tx, Arc::default(), Arc::default()));
        write_frame(&mut client, &Request::Status { name: None })
            .await
            .unwrap();
        let pending = rx.recv().await.unwrap();
        pending
            .response
            .send(Response::Ok {
                message: "x".repeat(MAX_FRAME_BYTES - 256),
                status: None,
            })
            .unwrap();
        timeout(IO_TIMEOUT + Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        // A stalled reader gets an incomplete frame when the deadline closes the socket.
        assert!(read_frame::<Response, _>(&mut client).await.is_err());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn unprivileged_mutation_is_not_dispatched() {
        if crate::effective_uid() == 0 {
            return;
        }
        let (mut client, server) = UnixStream::pair().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(serve_connection(server, tx, Arc::default(), Arc::default()));
        write_frame(&mut client, &Request::DownAll).await.unwrap();
        let response: Response = read_frame(&mut client).await.unwrap();
        assert!(matches!(response, Response::Error { exit_status: 5, .. }));
        task.await.unwrap();
        assert!(rx.recv().await.is_none());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn client_authenticates_server_before_sending_a_profile() {
        if crate::effective_uid() == 0 {
            return;
        }
        let (client, mut connection) = UnixStream::pair().unwrap();
        let result = call_authenticated(client, &Request::Status { name: None }).await;
        assert!(result.unwrap_err().to_string().contains("owned by root"));
        let mut bytes = Vec::new();
        connection.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }
}
