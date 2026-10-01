// SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};
use tokio::time::{Duration, Instant};

const SETTLE_DELAY: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkState {
    Idle,
    Applying,
    Ready,
    Recovering,
    Blocked,
    Disconnecting,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protection {
    NotRequired,
    Verified,
    Unverified,
}

/// Stable reason codes describe operations, never error text or profile data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    DirtyStartup,
    SupervisorUnavailable,
    NetworkChanged,
    Interface,
    FirewallApply,
    FirewallVerify,
    StateCleanup,
    Routes,
    Dns,
    Journal,
    Rollback,
    Cleanup,
}

impl FailureStage {
    pub fn is_protection(self) -> bool {
        matches!(
            self,
            Self::FirewallApply | Self::FirewallVerify | Self::StateCleanup
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub state: NetworkState,
    pub protection: Protection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<FailureStage>,
}

#[derive(Clone, Debug)]
pub struct Retry {
    pub deadline: Instant,
    pub attempts: u32,
    pub reason: FailureStage,
}

#[derive(Clone, Debug)]
pub enum State {
    Idle,
    Applying,
    Ready,
    Recovering(Retry),
    Blocked(Retry),
    Disconnecting,
    RecoveryRequired(FailureStage),
}

#[derive(Clone, Debug)]
pub struct Machine {
    pub state: State,
    pub protection: Protection,
}

#[derive(Clone, Copy, Debug)]
pub enum Event {
    Apply,
    Disconnect,
    DisconnectAll,
    StopAutomaticRecovery,
    NetworkChanged,
    RetryDue,
    ProtectionVerified { required: bool },
    Complete { has_profiles: bool },
    Failed(FailureStage),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    None,
    Apply,
    Disconnect,
    RestoreProtection,
    Reject,
}

impl Machine {
    pub fn new(dirty: bool) -> Self {
        Self {
            state: if dirty {
                State::RecoveryRequired(FailureStage::DirtyStartup)
            } else {
                State::Idle
            },
            protection: if dirty {
                Protection::Unverified
            } else {
                Protection::NotRequired
            },
        }
    }

    pub fn status(&self) -> NetworkStatus {
        let (state, reason) = match &self.state {
            State::Idle => (NetworkState::Idle, None),
            State::Applying => (NetworkState::Applying, None),
            State::Ready => (NetworkState::Ready, None),
            State::Disconnecting => (NetworkState::Disconnecting, None),
            State::Recovering(retry) => (NetworkState::Recovering, Some(retry.reason)),
            State::Blocked(retry) => (NetworkState::Blocked, Some(retry.reason)),
            State::RecoveryRequired(reason) => (NetworkState::RecoveryRequired, Some(*reason)),
        };
        NetworkStatus {
            state,
            protection: self.protection,
            reason,
        }
    }

    pub fn recovery_required(&self) -> bool {
        matches!(self.state, State::RecoveryRequired(_))
    }

    pub fn recovery_pending(&self) -> bool {
        matches!(self.state, State::Blocked(_) | State::RecoveryRequired(_))
    }

    pub fn deadline(&self) -> Option<Instant> {
        match &self.state {
            State::Recovering(retry) | State::Blocked(retry) => Some(retry.deadline),
            _ => None,
        }
    }

    /// Pure decisions with an explicit clock. All effects execute serially in the
    /// supervisor; timers only enqueue another attempt and never mutate networking.
    pub fn transition(&mut self, event: Event, now: Instant) -> Effect {
        let before = self.status();
        let effect = match event {
            Event::Apply | Event::Disconnect if self.recovery_pending() => Effect::Reject,
            Event::Apply => {
                self.state = State::Applying;
                Effect::Apply
            }
            Event::Disconnect | Event::DisconnectAll => {
                // Replacing the state cancels its timer even if cleanup fails.
                self.state = State::Disconnecting;
                Effect::Disconnect
            }
            Event::StopAutomaticRecovery => {
                if let State::Recovering(retry) | State::Blocked(retry) = &self.state {
                    self.state = State::RecoveryRequired(retry.reason);
                }
                Effect::None
            }
            Event::NetworkChanged => {
                match &mut self.state {
                    State::Ready => {
                        self.state = State::Recovering(Retry {
                            deadline: now + SETTLE_DELAY,
                            attempts: 0,
                            reason: FailureStage::NetworkChanged,
                        })
                    }
                    State::Recovering(retry) | State::Blocked(retry) => {
                        retry.deadline = retry.deadline.min(now + SETTLE_DELAY);
                    }
                    _ => {}
                }
                Effect::None
            }
            Event::RetryDue => {
                if self.deadline().is_some_and(|deadline| deadline <= now) {
                    Effect::RestoreProtection
                } else {
                    Effect::None
                }
            }
            Event::ProtectionVerified { required } => {
                self.protection = if required {
                    Protection::Verified
                } else {
                    Protection::NotRequired
                };
                if let State::Blocked(retry) = &self.state {
                    self.state = State::Recovering(retry.clone());
                }
                Effect::None
            }
            Event::Complete { has_profiles } => {
                // A caller must have verified the policy (or its removal) first.
                assert_ne!(self.protection, Protection::Unverified);
                self.state = if has_profiles {
                    State::Ready
                } else {
                    State::Idle
                };
                Effect::None
            }
            Event::Failed(stage) => {
                if stage.is_protection() {
                    self.protection = Protection::Unverified;
                }
                if stage.is_protection()
                    || matches!(stage, FailureStage::Routes | FailureStage::Dns)
                {
                    let attempts = match &self.state {
                        State::Recovering(retry) | State::Blocked(retry) => retry.attempts,
                        _ => 0,
                    };
                    let delay = Duration::from_secs((1_u64 << attempts.min(5)).min(30));
                    let retry = Retry {
                        deadline: now + delay,
                        attempts: attempts.saturating_add(1),
                        reason: stage,
                    };
                    self.state = if stage.is_protection() {
                        State::Blocked(retry)
                    } else {
                        State::Recovering(retry)
                    };
                } else {
                    if matches!(stage, FailureStage::Rollback | FailureStage::Cleanup) {
                        self.protection = Protection::Unverified;
                    }
                    self.state = State::RecoveryRequired(stage);
                }
                Effect::None
            }
        };
        let after = self.status();
        if before != after || matches!(event, Event::Failed(_)) {
            tracing::info!(from = ?before.state, to = ?after.state, protection = ?after.protection,
                reason = ?after.reason, retry_ms = ?self.deadline().map(|deadline| deadline.saturating_duration_since(now).as_millis()),
                "supervisor state transition");
        }
        effect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready(now: Instant) -> Machine {
        let mut machine = Machine::new(false);
        machine.transition(Event::Apply, now);
        machine.transition(Event::ProtectionVerified { required: true }, now);
        machine.transition(Event::Complete { has_profiles: true }, now);
        machine
    }

    #[test]
    fn rapid_changes_invalidate_immediately_without_postponing_deadline() {
        let now = Instant::now();
        let mut machine = ready(now);
        machine.transition(Event::NetworkChanged, now);
        assert_eq!(machine.status().state, NetworkState::Recovering);
        let deadline = now + SETTLE_DELAY;
        for milliseconds in [10, 50, 200] {
            machine.transition(
                Event::NetworkChanged,
                now + Duration::from_millis(milliseconds),
            );
            assert_eq!(machine.deadline(), Some(deadline));
        }
        assert_eq!(machine.transition(Event::RetryDue, now), Effect::None);
        assert_eq!(
            machine.transition(Event::RetryDue, deadline),
            Effect::RestoreProtection
        );
    }

    #[test]
    fn returning_network_advances_backoff_without_resetting_attempts_or_unblocking() {
        let mut now = Instant::now();
        let mut machine = ready(now);
        for seconds in [1, 2, 4, 8, 16, 30, 30] {
            machine.transition(Event::Failed(FailureStage::FirewallVerify), now);
            assert_eq!(machine.deadline(), Some(now + Duration::from_secs(seconds)));
            now = machine.deadline().unwrap();
        }
        machine.transition(Event::Failed(FailureStage::FirewallApply), now);
        machine.transition(Event::NetworkChanged, now);
        assert_eq!(machine.deadline(), Some(now + SETTLE_DELAY));
        assert_eq!(machine.status().state, NetworkState::Blocked);
        assert_eq!(machine.protection, Protection::Unverified);
        machine.transition(Event::ProtectionVerified { required: true }, now);
        machine.transition(Event::Failed(FailureStage::Routes), now);
        assert_eq!(machine.deadline(), Some(now + Duration::from_secs(30)));
    }

    #[test]
    fn disconnect_all_cancels_retries_and_blocks_new_profile_changes() {
        let now = Instant::now();
        for stage in [
            FailureStage::FirewallVerify,
            FailureStage::Journal,
            FailureStage::Rollback,
            FailureStage::Cleanup,
        ] {
            let mut machine = ready(now);
            machine.transition(Event::Failed(stage), now);
            assert_eq!(machine.transition(Event::Apply, now), Effect::Reject);
            assert_eq!(machine.transition(Event::Disconnect, now), Effect::Reject);
            assert_eq!(
                machine.transition(Event::DisconnectAll, now),
                Effect::Disconnect
            );
            assert!(machine.deadline().is_none());
            machine.transition(Event::ProtectionVerified { required: false }, now);
            machine.transition(
                Event::Complete {
                    has_profiles: false,
                },
                now,
            );
            machine.transition(Event::NetworkChanged, now);
            assert_eq!(machine.status().state, NetworkState::Idle);
            assert!(machine.deadline().is_none());
        }
    }
}
