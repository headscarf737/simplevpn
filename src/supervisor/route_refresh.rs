// SPDX-License-Identifier: GPL-3.0-or-later

use tokio::time::{Duration, Instant};

use crate::Result;

const SETTLE_DELAY: Duration = Duration::from_millis(250);
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

pub struct RouteRefresh {
    deadline: Option<Instant>,
    retry_delay: Duration,
    reconnecting: bool,
}

impl Default for RouteRefresh {
    fn default() -> Self {
        Self {
            deadline: None,
            retry_delay: INITIAL_RETRY_DELAY,
            reconnecting: false,
        }
    }
}

impl RouteRefresh {
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn is_reconnecting(&self) -> bool {
        self.reconnecting
    }

    pub fn request(&mut self, now: Instant) {
        // Coalesce notifications without postponing an existing attempt. A
        // returning link can bring a backed-off retry forward.
        let deadline = now + SETTLE_DELAY;
        self.deadline = Some(
            self.deadline
                .map_or(deadline, |pending| pending.min(deadline)),
        );
    }

    pub fn complete(&mut self, result: Result<()>, now: Instant) {
        match result {
            Ok(()) => {
                if self.reconnecting {
                    tracing::info!("VPN routes restored after network change");
                }
                self.clear();
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    retry_in_seconds = self.retry_delay.as_secs(),
                    "route refresh failed; retaining VPN protection and retrying"
                );
                self.reconnecting = true;
                self.deadline = Some(now + self.retry_delay);
                self.retry_delay = (self.retry_delay * 2).min(MAX_RETRY_DELAY);
            }
        }
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppError;

    fn missing_route() -> Result<()> {
        Err(AppError::Runtime(
            "route 192.0.2.1/32 was not installed".into(),
        ))
    }

    #[test]
    fn transient_failure_retries_without_another_event_and_recovers() {
        let mut refresh = RouteRefresh::default();
        refresh.request(Instant::now());
        let first_attempt = refresh.deadline().unwrap();
        refresh.complete(missing_route(), first_attempt);
        assert!(refresh.is_reconnecting());
        assert_eq!(
            refresh.deadline(),
            Some(first_attempt + Duration::from_secs(1))
        );
        refresh.complete(Ok(()), refresh.deadline().unwrap());
        assert!(!refresh.is_reconnecting());
        assert!(refresh.deadline().is_none());
    }

    #[test]
    fn network_loss_backs_off_but_link_return_advances_retry_without_starvation() {
        let mut now = Instant::now();
        let mut refresh = RouteRefresh::default();
        for seconds in [1, 2, 4, 8, 16, 30, 30] {
            refresh.complete(missing_route(), now);
            assert_eq!(refresh.deadline(), Some(now + Duration::from_secs(seconds)));
            now = refresh.deadline().unwrap();
        }
        refresh.complete(missing_route(), now);
        refresh.request(now + Duration::from_secs(1));
        let deadline = now + Duration::from_secs(1) + SETTLE_DELAY;
        assert_eq!(refresh.deadline(), Some(deadline));
        refresh.request(now + Duration::from_millis(1100));
        assert_eq!(refresh.deadline(), Some(deadline));
    }

    #[test]
    fn successful_disconnect_cancels_retry_and_resets_backoff() {
        let now = Instant::now();
        let mut refresh = RouteRefresh::default();
        refresh.complete(missing_route(), now);
        refresh.complete(missing_route(), refresh.deadline().unwrap());
        refresh.clear();
        assert!(refresh.deadline().is_none());
        assert!(!refresh.is_reconnecting());
        refresh.complete(missing_route(), now);
        assert_eq!(refresh.deadline(), Some(now + INITIAL_RETRY_DELAY));
    }
}
