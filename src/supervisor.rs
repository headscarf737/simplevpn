// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(target_os = "macos")]
mod route_refresh;

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

    use super::route_refresh::RouteRefresh;
    use crate::{
        AppError, Result,
        config::Profile,
        firewall::{FirewallPlan, generate as generate_firewall},
        ipc::{AppSessions, ControlAccess, PendingRequest, Request, Response, serve_connection},
        journal::{JournalStore, RecoveryJournal, TransitionStage},
        planner::{
            ActiveProfile, AggregatePlan, PlannedRoute, RoutePurpose, aggregate, validate_candidate,
        },
        platform::{MacRuntime, Tunnel},
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
        let stale_recovery = loaded.dirty;
        let runtime = MacRuntime::new().await?;
        let mut supervisor = Supervisor {
            runtime,
            tunnels: HashMap::new(),
            journal_store: store,
            journal: loaded,
            status_path,
            stale_recovery,
            route_refresh: RouteRefresh::default(),
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
                connection = listener.accept() => Event::Connection(connection),
                Some(request) = request_rx.recv() => Event::Request(request),
                Some(_) = clients.join_next(), if !clients.is_empty() => Event::ClientFinished,
                _ = session_changes.changed() => Event::SessionsChanged,
                Some(()) = supervisor.runtime.route_changed() => Event::RouteChange,
                () = sleep_until(supervisor.route_refresh.deadline().unwrap_or_else(Instant::now)), if supervisor.route_refresh.deadline().is_some() => Event::RefreshRoutes,
                _ = interrupt.recv() => Event::Signal,
                _ = terminate.recv() => Event::Signal,
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
                        supervisor.stale_recovery,
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
                        supervisor.stale_recovery,
                    ) {
                        break;
                    }
                }
                Event::RouteChange => {
                    if !supervisor.tunnels.is_empty() && !supervisor.stale_recovery {
                        supervisor.route_refresh.request(Instant::now());
                    }
                }
                Event::RefreshRoutes => supervisor.refresh_routes().await,
                Event::Signal => {
                    if !supervisor.tunnels.is_empty()
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
        supervisor.runtime.stop().await?;
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

    struct Supervisor<'a> {
        runtime: MacRuntime,
        tunnels: HashMap<String, Tunnel>,
        journal_store: JournalStore,
        journal: RecoveryJournal,
        status_path: &'a Path,
        stale_recovery: bool,
        route_refresh: RouteRefresh,
    }

    impl Supervisor<'_> {
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

        async fn up(&mut self, profile: Profile) -> Result<()> {
            let recovering = self.stale_recovery;
            self.recover_if_needed().await?;
            if self.tunnels.is_empty() && !recovering {
                self.runtime.cleanup_orphaned_firewall()?;
            }
            let tunnel = Tunnel::start(profile).await?;
            let candidate = tunnel.active_profile();
            let old_active = self.active_profiles();
            if let Err(error) = validate_candidate(&old_active, &candidate) {
                return match tunnel.stop().await {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(AppError::Runtime(format!(
                        "{error}; interface cleanup also failed: {cleanup_error}"
                    ))),
                };
            }
            let old_plan = aggregate(&old_active);
            let old_firewall = generate_firewall(&old_active, &old_plan);
            let mut new_active = old_active.clone();
            new_active.push(candidate.clone());
            let new_plan = aggregate(&new_active);
            let new_firewall = generate_firewall(&new_active, &new_plan);

            self.prepare_transition(&old_plan, new_plan.dns.is_some())?;
            self.journal.stage = TransitionStage::Interface;
            self.journal_store.save(&self.journal)?;
            self.tunnels.insert(candidate.name.clone(), tunnel);

            let endpoint_stage = endpoint_stage(&old_plan, &new_plan);
            let result = self
                .apply_transition(&endpoint_stage, &new_plan, &new_firewall)
                .await;
            if let Err(error) = result {
                let tunnel = self.tunnels.remove(&candidate.name);
                let rollback = self.rollback(&old_plan, &old_firewall, &old_active).await;
                let tunnel_cleanup = if let Some(tunnel) = tunnel {
                    tunnel.stop().await
                } else {
                    Ok(())
                };
                if rollback.is_err() || tunnel_cleanup.is_err() {
                    self.stale_recovery = true;
                }
                self.publish_status()?;
                return match (rollback, tunnel_cleanup) {
                    (Ok(()), Ok(())) => Err(error),
                    (rollback, cleanup) => {
                        let mut failures = vec![error.to_string()];
                        if let Err(rollback_error) = rollback {
                            failures.push(format!("rollback also failed: {rollback_error}"));
                        }
                        if let Err(cleanup_error) = cleanup {
                            failures
                                .push(format!("interface cleanup also failed: {cleanup_error}"));
                        }
                        Err(AppError::Runtime(failures.join("; ")))
                    }
                };
            }
            self.stale_recovery = false;
            self.route_refresh.clear();
            self.publish_status()
        }

        async fn down(&mut self, name: &str) -> Result<()> {
            if !self.tunnels.contains_key(name) {
                return Err(AppError::UnknownProfile(name.to_owned()));
            }
            self.transition_down(&[name.to_owned()]).await
        }

        async fn down_all(&mut self) -> Result<()> {
            if self.tunnels.is_empty() {
                let recovering = self.stale_recovery;
                self.recover_if_needed().await?;
                if !recovering {
                    self.runtime.cleanup_orphaned_firewall()?;
                }
                self.journal = RecoveryJournal::clean();
                self.journal_store.save(&self.journal)?;
                self.route_refresh.clear();
                self.publish_status()?;
                return Ok(());
            }
            let names: Vec<_> = self.tunnels.keys().cloned().collect();
            self.transition_down(&names).await
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
            self.prepare_transition(&old_plan, new_plan.dns.is_some())?;
            let endpoint_stage = endpoint_stage(&old_plan, &new_plan);
            let result = self
                .apply_transition(&endpoint_stage, &new_plan, &new_firewall)
                .await;
            if let Err(error) = result {
                let rollback = self.rollback(&old_plan, &old_firewall, &old_active).await;
                self.publish_status()?;
                return match rollback {
                    Ok(()) => Err(error),
                    Err(rollback_error) => Err(AppError::Runtime(format!(
                        "{error}; rollback also failed: {rollback_error}"
                    ))),
                };
            }
            let mut stop_errors = Vec::new();
            for name in names {
                if let Some(tunnel) = self.tunnels.remove(name)
                    && let Err(error) = tunnel.stop().await
                {
                    stop_errors.push(error.to_string());
                }
            }
            if !stop_errors.is_empty() {
                return Err(AppError::Runtime(stop_errors.join("; ")));
            }
            if self.tunnels.is_empty() {
                self.journal = RecoveryJournal::clean();
                self.journal_store.save(&self.journal)?;
            }
            self.stale_recovery = false;
            self.route_refresh.clear();
            self.publish_status()
        }

        async fn apply_transition(
            &mut self,
            endpoint_stage: &[PlannedRoute],
            plan: &AggregatePlan,
            firewall: &FirewallPlan,
        ) -> Result<()> {
            self.runtime.prepare_routes(endpoint_stage).await?;
            // Install protection (and evict bypassing states) before any route
            // mutation. A crash or failed route update must leave the guard up.
            // Removing the final policy is deferred until routes and DNS reset.
            if firewall.is_active() {
                self.apply_journaled_firewall(firewall)?;
            }
            self.journal.stage = TransitionStage::EndpointRoutes;
            self.journal.record_routes(endpoint_stage);
            self.journal_store.save(&self.journal)?;
            self.runtime.apply_routes(endpoint_stage).await?;

            self.runtime.prepare_routes(&plan.routes).await?;
            self.journal.stage = TransitionStage::AggregateRoutes;
            self.journal.record_routes(&plan.routes);
            self.journal_store.save(&self.journal)?;
            self.runtime.apply_routes(&plan.routes).await?;

            self.journal.stage = TransitionStage::Dns;
            self.journal_store.save(&self.journal)?;
            self.runtime.apply_dns(plan)?;
            if !firewall.is_active() {
                self.apply_journaled_firewall(firewall)?;
            }
            Ok(())
        }

        fn apply_journaled_firewall(&mut self, firewall: &FirewallPlan) -> Result<()> {
            self.runtime.prepare_firewall()?;
            self.journal.stage = TransitionStage::Firewall;
            self.journal.pf_anchor_installed |= firewall.is_active();
            self.journal.pf_was_enabled = self.runtime.pf_original_state();
            self.journal_store.save(&self.journal)?;
            self.runtime.apply_firewall(firewall)?;
            self.journal.pf_anchor_installed = firewall.is_active();
            self.journal_store.save(&self.journal)
        }

        async fn rollback(
            &mut self,
            plan: &AggregatePlan,
            firewall: &FirewallPlan,
            active: &[ActiveProfile],
        ) -> Result<()> {
            let mut errors = Vec::new();
            if let Err(error) = self.runtime.apply_dns(plan) {
                errors.push(error.to_string());
            }
            if firewall.is_active()
                && let Err(error) = self.runtime.apply_firewall(firewall)
            {
                errors.push(error.to_string());
            }
            if let Err(error) = self.runtime.apply_routes(&plan.routes).await {
                errors.push(error.to_string());
            }
            if errors.is_empty()
                && !firewall.is_active()
                && let Err(error) = self.runtime.apply_firewall(firewall)
            {
                errors.push(error.to_string());
            }
            if errors.is_empty() {
                if active.is_empty() {
                    self.journal = RecoveryJournal::clean();
                } else {
                    self.journal.dirty = true;
                    self.journal.stage = TransitionStage::Dns;
                    self.journal.record_routes(&plan.routes);
                    self.journal.pf_anchor_installed = firewall.is_active();
                    self.journal.pf_was_enabled = self.runtime.pf_original_state();
                }
                self.journal_store.save(&self.journal)
            } else {
                self.stale_recovery = true;
                Err(AppError::Runtime(errors.join("; ")))
            }
        }

        fn prepare_transition(
            &mut self,
            current: &AggregatePlan,
            will_use_dns: bool,
        ) -> Result<()> {
            if self.journal.dns_snapshot.is_none() && will_use_dns {
                self.journal.dns_snapshot = Some(self.runtime.dns_snapshot()?);
            }
            self.journal.version = crate::journal::JOURNAL_VERSION;
            self.journal.dirty = true;
            self.journal.stage = TransitionStage::Prepared;
            self.journal.record_routes(&current.routes);
            self.journal_store.save(&self.journal)
        }

        async fn recover_if_needed(&mut self) -> Result<()> {
            if !self.stale_recovery {
                return Ok(());
            }
            self.runtime.recover_stale(&self.journal).await?;
            self.journal = RecoveryJournal::clean();
            self.journal_store.save(&self.journal)?;
            self.stale_recovery = false;
            self.publish_status()
        }

        async fn refresh_routes(&mut self) {
            if self.tunnels.is_empty() || self.stale_recovery {
                self.route_refresh.clear();
                return;
            }
            // A network change can temporarily invalidate routes. Keep the
            // supervisor, tunnels and firewall alive while retrying, with the
            // control loop free to serve requests between attempts.
            let result = self.recompute_after_default_route_change().await;
            self.route_refresh.complete(result, Instant::now());
            if let Err(error) = self.publish_status() {
                tracing::error!(%error, "cannot publish route refresh status");
            }
        }

        async fn recompute_after_default_route_change(&mut self) -> Result<()> {
            if self.tunnels.is_empty() {
                return Ok(());
            }
            let active = self.active_profiles();
            let plan = aggregate(&active);
            // Keep protection installed across the entire refresh and backoff.
            // Reassert it and evict bypassing states before changing any route.
            // A firewall failure stops this attempt before route mutation.
            self.apply_journaled_firewall(&generate_firewall(&active, &plan))?;
            self.runtime.apply_routes(&plan.routes).await?;
            self.journal.record_routes(&plan.routes);
            self.journal.stage = TransitionStage::Dns;
            self.journal_store.save(&self.journal)
        }

        fn active_profiles(&self) -> Vec<ActiveProfile> {
            self.tunnels.values().map(Tunnel::active_profile).collect()
        }

        fn status(&self, name: Option<&str>) -> Result<StatusReport> {
            let active = self.active_profiles();
            let plan = aggregate(&active);
            let mut report = StatusReport::build(&active, &plan, self.stale_recovery);
            if self.route_refresh.is_reconnecting() {
                report.mark_reconnecting();
            }
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
