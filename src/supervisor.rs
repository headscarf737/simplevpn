// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(target_os = "macos")]
pub(crate) mod operations;
pub(crate) mod state;

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        collections::HashMap,
        fs,
        os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
        path::Path,
        sync::Arc,
        time::Duration,
    };

    use tokio::{
        net::{UnixListener, UnixStream},
        signal::unix::{SignalKind, signal},
        sync::mpsc,
        task::JoinSet,
        time::{Instant, sleep_until},
    };

    use super::{
        operations::{Failure, NetworkOperations, OperationResult},
        state::{Effect, Event as StateEvent, FailureStage, Machine, State},
    };
    use crate::{
        AppError, Result,
        config::Profile,
        firewall::{FirewallPlan, generate as generate_firewall},
        ipc::{AppSessions, ControlAccess, PendingRequest, Request, Response, serve_connection},
        journal::{JournalStore, RecoveryJournal, TransitionStage},
        planner::{
            ActiveProfile, AggregatePlan, PlannedRoute, RoutePurpose, aggregate, validate_candidate,
        },
        platform::MacRuntime,
        status::{StatusReport, write_atomic},
    };

    const MAX_CLIENTS: usize = 32;
    const IDLE_TIMEOUT: Duration = Duration::from_secs(15);

    // Tunnels and live app sessions keep the supervisor running. CLI-only
    // startup/failures retain the bounded grace period; status polls and
    // account grants never extend it.
    #[derive(Default)]
    struct Lifetime {
        idle_deadline: Option<Instant>,
    }

    impl Lifetime {
        fn observe(&mut self, has_tunnels: bool, has_apps: bool) {
            if has_tunnels || has_apps {
                self.idle_deadline = None;
            } else {
                self.idle_deadline
                    .get_or_insert_with(|| Instant::now() + IDLE_TIMEOUT);
            }
        }

        fn finished_request(
            &mut self,
            vpn_change: bool,
            succeeded: bool,
            has_tunnels: bool,
            recovery_pending: bool,
            has_apps: bool,
        ) -> bool {
            self.observe(has_tunnels, has_apps);
            vpn_change && succeeded && !has_tunnels && !has_apps && !recovery_pending
        }

        fn sessions_changed(
            &mut self,
            has_tunnels: bool,
            has_apps: bool,
            recovery_pending: bool,
        ) -> bool {
            self.observe(has_tunnels, has_apps);
            !has_apps && !has_tunnels && !recovery_pending
        }
    }

    pub async fn run(
        runtime_directory: &Path,
        socket_path: &Path,
        status_path: &Path,
        journal_path: &Path,
    ) -> Result<()> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("simplevpn=info,talpid_routing=debug")
                }),
            )
            .with_target(false)
            .try_init();
        prepare_runtime_directory(runtime_directory)?;
        // Serialize startup before stale-socket cleanup or journal recovery. A
        // connect-then-unlink check alone races with another starting supervisor.
        let lock_path = runtime_directory.join("supervisor.lock");
        let _lock = crate::secure_fs::lock_supervisor(&lock_path).map_err(|error| {
            AppError::Runtime(format!("cannot acquire supervisor lock: {error}"))
        })?;
        let listener = bind_listener(socket_path)?;
        let store = JournalStore::new(journal_path);
        let loaded = store.load()?.unwrap_or_else(RecoveryJournal::clean);
        let machine = Machine::new(loaded.dirty);
        let runtime = MacRuntime::new().await?;
        let mut supervisor = Supervisor {
            runtime,
            tunnels: HashMap::new(),
            pending_cleanup: Vec::new(),
            cleanup_guard: None,
            journal_store: store,
            journal: loaded,
            status_path,
            machine,
        };
        supervisor.publish_status()?;
        tracing::info!("supervisor initialized");

        let mut interrupt = signal(SignalKind::interrupt())
            .map_err(|error| AppError::Runtime(format!("cannot monitor SIGINT: {error}")))?;
        let mut terminate = signal(SignalKind::terminate())
            .map_err(|error| AppError::Runtime(format!("cannot monitor SIGTERM: {error}")))?;

        let (request_tx, mut request_rx) = mpsc::channel::<PendingRequest>(MAX_CLIENTS);
        let access = Arc::new(ControlAccess::default());
        let sessions = Arc::new(AppSessions::default());
        let mut session_changes = sessions.subscribe();
        let mut clients = JoinSet::new();
        let mut lifetime = Lifetime::default();
        lifetime.observe(false, false);
        loop {
            enum Event {
                Connection(std::io::Result<(UnixStream, tokio::net::unix::SocketAddr)>),
                Request(PendingRequest),
                ClientFinished,
                SessionsChanged,
                RouteChange,
                RefreshRoutes,
                Signal,
                Idle,
            }
            let event = tokio::select! {
                biased;
                _ = interrupt.recv() => Event::Signal,
                _ = terminate.recv() => Event::Signal,
                // Queued commands get a turn between recovery attempts. A due
                // attempt also precedes new notifications to prevent starvation.
                Some(request) = request_rx.recv() => Event::Request(request),
                () = sleep_until(supervisor.machine.deadline().unwrap_or_else(Instant::now)), if supervisor.machine.deadline().is_some() => Event::RefreshRoutes,
                connection = listener.accept() => Event::Connection(connection),
                Some(_) = clients.join_next(), if !clients.is_empty() => Event::ClientFinished,
                _ = session_changes.changed() => Event::SessionsChanged,
                Some(()) = supervisor.runtime.route_changed() => Event::RouteChange,
                () = sleep_until(lifetime.idle_deadline.unwrap_or_else(Instant::now)), if lifetime.idle_deadline.is_some() => Event::Idle,
            };
            match event {
                Event::Connection(Ok((stream, _))) => {
                    if clients.len() < MAX_CLIENTS {
                        clients.spawn(serve_connection(
                            stream,
                            request_tx.clone(),
                            access.clone(),
                            sessions.clone(),
                        ));
                    }
                }
                Event::Connection(Err(error)) => {
                    return Err(AppError::Runtime(format!("control socket failed: {error}")));
                }
                Event::Request(pending) => {
                    let vpn_change = pending.request.changes_vpn();
                    let outcome = supervisor
                        .dispatch(pending.request, pending.peer_uid, &access)
                        .await;
                    let succeeded = outcome.is_ok();
                    let response = match outcome {
                        Ok((message, status)) => Response::Ok {
                            message,
                            status: Some(status),
                        },
                        Err(error) => Response::from_error(&error),
                    };
                    let _ = pending.response.send(response);
                    if lifetime.finished_request(
                        vpn_change,
                        succeeded,
                        !supervisor.tunnels.is_empty(),
                        supervisor.machine.recovery_pending(),
                        sessions.active(),
                    ) {
                        break;
                    }
                }
                Event::ClientFinished => {}
                Event::SessionsChanged => {
                    if lifetime.sessions_changed(
                        !supervisor.tunnels.is_empty(),
                        sessions.active(),
                        supervisor.machine.recovery_pending(),
                    ) {
                        break;
                    }
                }
                Event::RouteChange => {
                    supervisor.event(StateEvent::NetworkChanged);
                    if let Err(error) = supervisor.publish_status() {
                        tracing::error!(%error, "cannot publish network change status");
                    }
                }
                Event::RefreshRoutes => supervisor.refresh_routes().await,
                Event::Signal => {
                    if supervisor.has_resources()
                        && let Err(error) = supervisor.down_all().await
                    {
                        tracing::error!(%error, "clean signal teardown failed");
                    }
                    break;
                }
                Event::Idle => {
                    // A session may have arrived while the deadline became ready.
                    if !sessions.active() {
                        break;
                    }
                    lifetime.observe(!supervisor.tunnels.is_empty(), true);
                }
            }
        }

        // Let completed commands receive their reply. Client reads and writes have
        // deadlines, and closing the queue releases any pending response waiters.
        sessions.stop();
        drop(request_rx);
        while clients.join_next().await.is_some() {}
        supervisor
            .runtime
            .stop(matches!(supervisor.machine.state, State::Idle) && !supervisor.journal.dirty)
            .await?;
        if let Err(error) = fs::remove_file(socket_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "cannot remove supervisor socket");
        }
        if socket_path.exists() {
            return Err(AppError::Runtime(
                "system write verification failed: supervisor socket still exists after removal"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod lifetime_tests {
        use super::*;

        #[test]
        fn app_session_survives_disconnect_all_and_exits_when_last_app_closes() {
            let mut lifetime = Lifetime::default();
            assert!(!lifetime.sessions_changed(false, true, false));
            assert!(lifetime.idle_deadline.is_none());
            assert!(!lifetime.finished_request(true, true, false, false, true));
            assert!(lifetime.idle_deadline.is_none());
            assert!(!lifetime.sessions_changed(false, true, false));
            assert!(lifetime.sessions_changed(false, false, false));
        }

        #[test]
        fn quitting_app_preserves_vpns_until_last_cli_disconnect() {
            let mut lifetime = Lifetime::default();
            assert!(!lifetime.sessions_changed(true, false, false));
            assert!(lifetime.idle_deadline.is_none());
            assert!(lifetime.finished_request(true, true, false, false, false));
        }

        #[test]
        fn closing_app_with_pending_recovery_keeps_bounded_cleanup_grace() {
            let mut lifetime = Lifetime::default();
            assert!(!lifetime.sessions_changed(false, false, true));
            assert!(lifetime.idle_deadline.is_some());
        }

        #[test]
        fn authorization_bootstrap_does_not_exit_before_the_first_connection() {
            let mut lifetime = Lifetime::default();
            lifetime.observe(false, false);
            let deadline = lifetime.idle_deadline;
            assert!(!lifetime.finished_request(
                Request::Authorize { uid: 501 }.changes_vpn(),
                true,
                false,
                false,
                false
            ));
            assert_eq!(lifetime.idle_deadline, deadline);
        }

        #[test]
        fn last_disconnect_exits_with_accounts_still_authorized() {
            let access = ControlAccess::default();
            access.authorize(0, 501).unwrap();
            access.authorize(0, 502).unwrap();
            for request in [
                Request::Down {
                    name: "last".to_owned(),
                },
                Request::DownAll,
            ] {
                let mut lifetime = Lifetime::default();
                lifetime.observe(true, false);
                assert!(lifetime.idle_deadline.is_none());
                assert!(lifetime.finished_request(
                    request.changes_vpn(),
                    true,
                    false,
                    false,
                    false
                ));
                assert!(access.check(501, &request).is_ok());
                assert!(access.check(502, &request).is_ok());
            }
        }

        #[test]
        fn connecting_or_disconnecting_with_vpns_remaining_keeps_the_supervisor() {
            let mut lifetime = Lifetime::default();
            lifetime.observe(false, false);
            for request in [
                Request::UpFile {
                    path: "/work.toml".into(),
                },
                Request::Down {
                    name: "other".to_owned(),
                },
            ] {
                assert!(!lifetime.finished_request(
                    request.changes_vpn(),
                    true,
                    true,
                    false,
                    false
                ));
                assert!(lifetime.idle_deadline.is_none());
            }
        }

        #[test]
        fn status_polls_and_failed_connections_do_not_extend_the_idle_deadline() {
            let mut lifetime = Lifetime::default();
            lifetime.observe(false, false);
            let deadline = lifetime.idle_deadline.unwrap();
            for _ in 0..10 {
                assert!(!lifetime.finished_request(
                    Request::Status { name: None }.changes_vpn(),
                    true,
                    false,
                    false,
                    false
                ));
                assert!(!lifetime.finished_request(true, false, false, true, false));
                assert_eq!(lifetime.idle_deadline, Some(deadline));
            }
        }
    }

    struct Supervisor<'a, R: NetworkOperations> {
        runtime: R,
        tunnels: HashMap<String, R::Tunnel>,
        pending_cleanup: Vec<R::Tunnel>,
        cleanup_guard: Option<FirewallPlan>,
        journal_store: JournalStore,
        journal: RecoveryJournal,
        status_path: &'a Path,
        machine: Machine,
    }

    impl<R: NetworkOperations> Supervisor<'_, R> {
        async fn dispatch(
            &mut self,
            request: Request,
            peer_uid: u32,
            access: &ControlAccess,
        ) -> Result<(String, StatusReport)> {
            access.check(peer_uid, &request)?;
            let request = match request {
                Request::UpFile { path } => Request::Up {
                    profile: Profile::load_secure(&path, peer_uid)?,
                },
                request => request,
            };
            match request {
                Request::AppSession => Ok(("App session opened".to_owned(), self.status(None)?)),
                Request::Authorize { uid } => {
                    access.authorize(peer_uid, uid)?;
                    Ok(("VPN control authorized".to_owned(), self.status(None)?))
                }
                Request::UpFile { .. } => unreachable!("profile path loaded above"),
                Request::Up { profile } => {
                    let name = profile.name.clone();
                    tracing::info!(profile = %name, "connecting profile");
                    self.up(profile.validate()?).await?;
                    tracing::info!(profile = %name, "profile connected");
                    Ok((format!("profile '{name}' is up"), self.status(None)?))
                }
                Request::Down { name } => {
                    tracing::info!(profile = %name, "disconnecting profile");
                    self.down(&name).await?;
                    tracing::info!(profile = %name, "profile disconnected");
                    Ok((format!("profile '{name}' is down"), self.status(None)?))
                }
                Request::DownAll => {
                    tracing::info!("disconnecting all profiles");
                    self.down_all().await?;
                    tracing::info!("all profiles disconnected");
                    Ok(("all profiles are down".to_owned(), self.status(None)?))
                }
                Request::Status { name } => {
                    let report = self.status(name.as_deref())?;
                    Ok((String::new(), report))
                }
            }
        }

        fn event(&mut self, event: StateEvent) -> Effect {
            self.machine.transition(event, self.runtime.now())
        }

        fn failed(&mut self, failure: Failure) -> AppError {
            tracing::warn!(stage = ?failure.stage, "supervisor operation failed");
            self.event(StateEvent::Failed(failure.stage));
            if let Err(error) = self.publish_status() {
                tracing::error!(%error, "cannot publish failed transition status");
            }
            failure.error
        }

        fn begin(&mut self, event: StateEvent) -> Result<()> {
            if self.event(event) == Effect::Reject {
                return Err(AppError::Runtime(
                    "recovery pending; use down --all".to_owned(),
                ));
            }
            // A cache publication failure must not strand an Applying state.
            if let Err(error) = self.publish_status() {
                tracing::error!(%error, "cannot publish transition status");
            }
            Ok(())
        }

        async fn up(&mut self, profile: Profile) -> Result<()> {
            // Preserve CLI startup recovery, but never replace live resources
            // while their cleanup or protection is unresolved.
            if self.machine.recovery_required() && !self.has_resources() {
                self.down_all().await?;
            }
            self.begin(StateEvent::Apply)?;
            let old_active = self.active_profiles();
            let old_plan = aggregate(&old_active);
            let old_firewall = generate_firewall(&old_active, &old_plan);
            self.prepare_transition(&old_plan, profile.dns.is_some())
                .map_err(|failure| self.failed(failure))?;
            if self.tunnels.is_empty() {
                self.runtime
                    .cleanup_orphaned_firewall()
                    .map_err(Failure::at(FailureStage::Cleanup))
                    .map_err(|failure| self.failed(failure))?;
            }
            let mut tunnel = match self.runtime.start_tunnel(profile).await {
                Ok(tunnel) => tunnel,
                Err(failure) => {
                    return Err(self
                        .failed_request(failure, &old_active, None, &old_firewall)
                        .await);
                }
            };
            let candidate = R::active_profile(&tunnel);
            if let Err(error) = validate_candidate(&old_active, &candidate) {
                if let Err(cleanup) = self.runtime.stop_tunnel(&mut tunnel).await {
                    self.pending_cleanup.push(tunnel);
                    return Err(self.failed(Failure::new(
                        FailureStage::Cleanup,
                        AppError::Runtime(format!(
                            "{error}; interface cleanup also failed: {cleanup}"
                        )),
                    )));
                }
                return Err(self
                    .failed_request(
                        Failure::new(FailureStage::Interface, error),
                        &old_active,
                        None,
                        &old_firewall,
                    )
                    .await);
            }
            self.tunnels.insert(candidate.name.clone(), tunnel);
            let new_active = self.active_profiles();
            let new_plan = aggregate(&new_active);
            let new_firewall = generate_firewall(&new_active, &new_plan);
            self.journal.stage = TransitionStage::Interface;
            // Journal failures leave resources owned for explicit cleanup.
            self.save_journal()
                .map_err(|failure| self.failed(failure))?;
            let result = self
                .apply_transition(
                    &endpoint_stage(&old_plan, &new_plan),
                    &new_plan,
                    &new_firewall,
                )
                .await;
            if let Err(failure) = result {
                return Err(self
                    .failed_request(failure, &old_active, Some(&candidate.name), &new_firewall)
                    .await);
            }
            self.finish_transition(&new_active, &new_firewall)
                .map_err(|failure| self.failed(failure))?;
            self.publish_status()
        }

        async fn down(&mut self, name: &str) -> Result<()> {
            if self.machine.recovery_pending() {
                return Err(AppError::Runtime(
                    "recovery pending; use down --all".to_owned(),
                ));
            }
            if !self.tunnels.contains_key(name) {
                return Err(AppError::UnknownProfile(name.to_owned()));
            }
            self.begin(StateEvent::Disconnect)?;
            self.transition_down(&[name.to_owned()]).await
        }

        async fn down_all(&mut self) -> Result<()> {
            let needs_recovery = self.machine.recovery_required();
            self.begin(StateEvent::DisconnectAll)?;
            let result = if needs_recovery || self.tunnels.is_empty() {
                self.cleanup_recorded().await
            } else {
                let names: Vec<_> = self.tunnels.keys().cloned().collect();
                self.transition_down(&names).await
            };
            if result.is_err() {
                // Disconnect All never schedules a retry. Preserve an already
                // verified rollback and the original failure classification.
                self.event(StateEvent::StopAutomaticRecovery);
                let _ = self.publish_status();
            }
            result
        }

        async fn cleanup_recorded(&mut self) -> Result<()> {
            let mut active = self.active_profiles();
            active.extend(self.pending_cleanup.iter().map(R::active_profile));
            let guard = self
                .cleanup_guard
                .clone()
                .unwrap_or_else(|| generate_firewall(&active, &aggregate(&active)));
            self.journal.dirty = true;
            self.save_journal()
                .map_err(|failure| self.failed(failure))?;
            self.runtime
                .recover_stale(&self.journal)
                .await
                .map_err(Failure::at(FailureStage::Cleanup))
                .map_err(|failure| self.failed(failure))?;
            self.stop_profiles(&self.tunnels.keys().cloned().collect::<Vec<_>>())
                .await
                .map_err(|failure| self.failed(failure))?;
            let cleanup = self
                .runtime
                .cleanup_recovered_firewall(&self.journal)
                .map_err(Failure::at(FailureStage::Cleanup))
                .and_then(|()| {
                    self.event(StateEvent::ProtectionVerified { required: false });
                    self.commit_journal(RecoveryJournal::clean())
                });
            if let Err(failure) = cleanup {
                self.restore_cleanup_guard(&guard);
                return Err(self.failed(failure));
            }
            self.cleanup_guard = None;
            self.event(StateEvent::Complete {
                has_profiles: false,
            });
            self.publish_status()
        }

        async fn transition_down(&mut self, names: &[String]) -> Result<()> {
            let old_active = self.active_profiles();
            let old_plan = aggregate(&old_active);
            let old_firewall = generate_firewall(&old_active, &old_plan);
            let new_active: Vec<_> = old_active
                .iter()
                .filter(|profile| !names.contains(&profile.name))
                .cloned()
                .collect();
            let new_plan = aggregate(&new_active);
            let new_firewall = generate_firewall(&new_active, &new_plan);
            self.prepare_transition(&old_plan, new_plan.dns.is_some())
                .map_err(|failure| self.failed(failure))?;
            // Keep the old protection, including a removed full-tunnel policy,
            // until route/DNS restoration and every requested tunnel stop pass.
            let guard = &old_firewall;
            if let Err(failure) = self
                .apply_transition(&endpoint_stage(&old_plan, &new_plan), &new_plan, guard)
                .await
            {
                return Err(self
                    .failed_request(failure, &old_active, None, &old_firewall)
                    .await);
            }
            if let Err(failure) = self.stop_profiles(names).await {
                self.cleanup_guard = Some(old_firewall.clone());
                return Err(self.failed(failure));
            }
            if !new_active.is_empty() {
                self.apply_journaled_firewall(&new_firewall)
                    .map_err(|failure| self.failed(failure))?;
            }
            self.finish_transition(&new_active, guard)
                .map_err(|failure| self.failed(failure))?;
            self.publish_status()
        }

        async fn stop_profiles(&mut self, names: &[String]) -> OperationResult {
            let mut errors = Vec::new();
            let mut pending = std::mem::take(&mut self.pending_cleanup);
            for name in names {
                if let Some(tunnel) = self.tunnels.remove(name) {
                    pending.push(tunnel);
                }
            }
            for mut tunnel in pending {
                if let Err(error) = self.runtime.stop_tunnel(&mut tunnel).await {
                    errors.push(error.to_string());
                    self.pending_cleanup.push(tunnel);
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(Failure::new(
                    FailureStage::Cleanup,
                    AppError::Runtime(errors.join("; ")),
                ))
            }
        }

        async fn apply_transition(
            &mut self,
            endpoints: &[PlannedRoute],
            plan: &AggregatePlan,
            guard: &FirewallPlan,
        ) -> OperationResult {
            if guard.is_active() {
                self.apply_journaled_firewall(guard)?;
            }
            self.apply_recorded_routes(endpoints, TransitionStage::EndpointRoutes)
                .await?;
            self.apply_recorded_routes(&plan.routes, TransitionStage::AggregateRoutes)
                .await?;
            self.journal.stage = TransitionStage::Dns;
            self.save_journal()?;
            self.runtime
                .apply_dns(plan)
                .map_err(Failure::at(FailureStage::Dns))
        }

        async fn apply_recorded_routes(
            &mut self,
            routes: &[PlannedRoute],
            stage: TransitionStage,
        ) -> OperationResult {
            self.runtime
                .prepare_routes(routes)
                .await
                .map_err(Failure::at(FailureStage::Routes))?;
            self.journal.stage = stage;
            // Keep the union until verification succeeds: failed writes can leave
            // either old or new routes behind, including a partially applied plan.
            for route in routes {
                let prefix = route.prefix.to_string();
                if !self.journal.routes.iter().any(|old| old.prefix == prefix) {
                    self.journal
                        .routes
                        .push(crate::journal::JournalRoute { prefix });
                }
            }
            self.save_journal()?;
            self.runtime
                .apply_routes(routes)
                .await
                .map_err(Failure::at(FailureStage::Routes))
        }

        fn apply_journaled_firewall(&mut self, firewall: &FirewallPlan) -> OperationResult {
            self.runtime
                .prepare_firewall()
                .map_err(Failure::at(FailureStage::FirewallApply))?;
            self.journal.stage = TransitionStage::Firewall;
            self.journal.pf_anchor_installed |= firewall.is_active();
            self.journal.pf_was_enabled = self.runtime.pf_original_state();
            self.save_journal()?;
            // Adapter success includes independent rule verification and eviction
            // of incompatible PF states. No other operation establishes Verified.
            self.runtime.apply_firewall(firewall)?;
            self.event(StateEvent::ProtectionVerified {
                required: firewall.is_active(),
            });
            // Retain the recovery flag until the clean journal is committed.
            // A failed final write may require reasserting the previous guard.
            self.journal.pf_anchor_installed |= firewall.is_active();
            self.save_journal()
        }

        async fn failed_request(
            &mut self,
            failure: Failure,
            old_active: &[ActiveProfile],
            candidate: Option<&str>,
            guard: &FirewallPlan,
        ) -> AppError {
            if matches!(failure.stage, FailureStage::Journal | FailureStage::Cleanup) {
                return self.failed(failure);
            }
            tracing::warn!(stage = ?failure.stage, "requested transition failed; verifying rollback");
            if failure.stage.is_protection() {
                self.event(StateEvent::Failed(failure.stage));
            }
            let old_plan = aggregate(old_active);
            let old_firewall = generate_firewall(old_active, &old_plan);
            let rollback_guard = if old_firewall.is_active() {
                &old_firewall
            } else {
                guard
            };
            let rollback = async {
                // Stop immediately on a failed protection check. DNS and routes
                // may only be restored behind verified required protection.
                self.apply_transition(&old_plan.routes, &old_plan, rollback_guard)
                    .await?;
                if let Some(name) = candidate {
                    self.stop_profiles(&[name.to_owned()]).await?;
                }
                self.finish_transition(old_active, rollback_guard)
            }
            .await;
            match rollback {
                Ok(()) => {
                    let _ = self.publish_status();
                    failure.error
                }
                Err(rollback) => {
                    tracing::warn!(stage = ?rollback.stage, "rollback failed");
                    if rollback.stage.is_protection() {
                        self.event(StateEvent::Failed(rollback.stage));
                    }
                    self.failed(Failure::new(
                        if rollback.stage == FailureStage::Journal {
                            FailureStage::Journal
                        } else {
                            FailureStage::Rollback
                        },
                        AppError::Runtime(format!(
                            "{}; rollback also failed: {}",
                            failure.error, rollback.error
                        )),
                    ))
                }
            }
        }

        fn finish_transition(
            &mut self,
            active: &[ActiveProfile],
            guard: &FirewallPlan,
        ) -> OperationResult {
            let plan = aggregate(active);
            if active.is_empty() {
                // Routes, DNS and tunnel cleanup have all passed verification.
                let empty = generate_firewall(active, &plan);
                let cleanup = self
                    .apply_journaled_firewall(&empty)
                    .and_then(|()| self.commit_journal(RecoveryJournal::clean()));
                if let Err(failure) = cleanup {
                    self.restore_cleanup_guard(guard);
                    return Err(failure);
                }
            } else {
                let mut committed = self.journal.clone();
                committed.record_routes(&plan.routes);
                committed.stage = TransitionStage::Dns;
                self.commit_journal(committed)?;
            }
            self.cleanup_guard = None;
            self.event(StateEvent::Complete {
                has_profiles: !active.is_empty(),
            });
            Ok(())
        }

        fn restore_cleanup_guard(&mut self, guard: &FirewallPlan) {
            if !guard.is_active() {
                return;
            }
            self.cleanup_guard = Some(guard.clone());
            self.journal.pf_anchor_installed = true;
            match self.runtime.apply_firewall(guard) {
                Ok(()) => {
                    self.event(StateEvent::ProtectionVerified { required: true });
                }
                Err(restore) => {
                    self.event(StateEvent::Failed(restore.stage));
                }
            }
        }

        fn prepare_transition(
            &mut self,
            current: &AggregatePlan,
            will_use_dns: bool,
        ) -> OperationResult {
            if self.journal.dns_snapshot.is_none() && will_use_dns {
                self.journal.dns_snapshot = Some(
                    self.runtime
                        .dns_snapshot()
                        .map_err(Failure::at(FailureStage::Dns))?,
                );
            }
            self.journal.dirty = true;
            self.journal.stage = TransitionStage::Prepared;
            for route in &current.routes {
                let prefix = route.prefix.to_string();
                if !self.journal.routes.iter().any(|old| old.prefix == prefix) {
                    self.journal
                        .routes
                        .push(crate::journal::JournalRoute { prefix });
                }
            }
            self.save_journal()
        }

        fn save_journal(&mut self) -> OperationResult {
            self.runtime
                .save_journal(&self.journal_store, &self.journal)
                .map_err(Failure::at(FailureStage::Journal))
        }

        fn commit_journal(&mut self, journal: RecoveryJournal) -> OperationResult {
            self.runtime
                .save_journal(&self.journal_store, &journal)
                .map_err(Failure::at(FailureStage::Journal))?;
            self.journal = journal;
            Ok(())
        }

        async fn refresh_routes(&mut self) {
            if self.event(StateEvent::RetryDue) != Effect::RestoreProtection {
                return;
            }
            let active = self.active_profiles();
            let plan = aggregate(&active);
            let firewall = generate_firewall(&active, &plan);
            let result = async {
                self.apply_journaled_firewall(&firewall)?;
                self.apply_recorded_routes(&plan.routes, TransitionStage::AggregateRoutes)
                    .await?;
                self.runtime
                    .apply_dns(&plan)
                    .map_err(Failure::at(FailureStage::Dns))?;
                self.finish_transition(&active, &firewall)
            }
            .await;
            if let Err(failure) = result {
                self.failed(failure);
            }
            if let Err(error) = self.publish_status() {
                tracing::error!(%error, "cannot publish recovery status");
            }
        }

        fn has_resources(&self) -> bool {
            !self.tunnels.is_empty() || !self.pending_cleanup.is_empty()
        }

        fn active_profiles(&self) -> Vec<ActiveProfile> {
            self.tunnels.values().map(R::active_profile).collect()
        }

        fn status(&self, name: Option<&str>) -> Result<StatusReport> {
            let active = self.active_profiles();
            let mut report = StatusReport::build(&active, &aggregate(&active), false);
            report.set_network_status(self.machine.status());
            let report = report.select(name);
            if let Some(name) = name
                && report.profiles.is_empty()
            {
                return Err(AppError::UnknownProfile(name.to_owned()));
            }
            Ok(report)
        }

        fn publish_status(&self) -> Result<()> {
            write_atomic(self.status_path, &self.status(None)?)
        }
    }

    #[cfg(test)]
    mod tests;

    fn endpoint_stage(old: &AggregatePlan, new: &AggregatePlan) -> Vec<PlannedRoute> {
        let mut routes: HashMap<_, _> = old
            .routes
            .iter()
            .cloned()
            .map(|route| (route.prefix, route))
            .collect();
        for route in &new.routes {
            if route.purpose == RoutePurpose::EndpointException {
                routes.insert(route.prefix, route.clone());
            }
        }
        routes.into_values().collect()
    }

    fn prepare_runtime_directory(path: &Path) -> Result<()> {
        crate::secure_fs::ensure_directory(path, 0o755).map_err(|error| {
            AppError::Platform(format!(
                "cannot secure runtime directory {}: {error}",
                path.display()
            ))
        })?;
        verify_metadata(path, 0o755, MetadataKind::Directory)
    }

    fn bind_listener(path: &Path) -> Result<UnixListener> {
        if fs::symlink_metadata(path).is_ok() {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(AppError::Runtime(
                    "another simplevpn supervisor is already running".to_owned(),
                ));
            }
            fs::remove_file(path).map_err(|error| {
                AppError::Runtime(format!("cannot remove stale control socket: {error}"))
            })?;
            if fs::symlink_metadata(path).is_ok() {
                return Err(AppError::Runtime(
                    "system write verification failed: stale control socket still exists"
                        .to_owned(),
                ));
            }
        }
        let listener = UnixListener::bind(path)
            .map_err(|error| AppError::Runtime(format!("cannot bind control socket: {error}")))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666)).map_err(|error| {
            AppError::Runtime(format!("cannot set socket permissions: {error}"))
        })?;
        verify_metadata(path, 0o666, MetadataKind::Socket)?;
        Ok(listener)
    }

    #[derive(Clone, Copy)]
    enum MetadataKind {
        Directory,
        Socket,
    }

    fn verify_metadata(path: &Path, expected_mode: u32, kind: MetadataKind) -> Result<()> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AppError::Runtime(format!("cannot verify {}: {error}", path.display()))
        })?;
        let type_matches = match kind {
            MetadataKind::Directory => metadata.file_type().is_dir(),
            MetadataKind::Socket => metadata.file_type().is_socket(),
        };
        // SAFETY: `geteuid` has no preconditions.
        let expected_uid = unsafe { libc::geteuid() };
        if !type_matches
            || metadata.file_type().is_symlink()
            || metadata.mode() & 0o777 != expected_mode
            || metadata.uid() != expected_uid
        {
            return Err(AppError::Runtime(format!(
                "system write verification failed: {} metadata is incorrect",
                path.display()
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub use macos::run;

#[cfg(not(target_os = "macos"))]
pub async fn run(
    _runtime_directory: &std::path::Path,
    _socket_path: &std::path::Path,
    _status_path: &std::path::Path,
    _journal_path: &std::path::Path,
) -> crate::Result<()> {
    Err(crate::AppError::Platform("macOS is required".to_owned()))
}
