// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg(target_os = "macos")]

use std::sync::Arc;

use gotatun::{
    noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
    packet::WgKind,
    x25519::{PublicKey, StaticSecret},
};

#[test]
fn in_memory_peers_with_a_preshared_key_complete_a_wireguard_handshake() {
    let alice_secret = StaticSecret::from([1_u8; 32]);
    let alice_public = PublicKey::from(&alice_secret);
    let bob_secret = StaticSecret::from([2_u8; 32]);
    let bob_public = PublicKey::from(&bob_secret);
    let preshared_key = Some([3_u8; 32]);
    let mut alice = Tunn::new(
        alice_secret,
        bob_public,
        preshared_key,
        Some(25),
        IndexTable::from_os_rng(),
        Arc::new(RateLimiter::new(&alice_public, 100)),
    );
    let mut bob = Tunn::new(
        bob_secret,
        alice_public,
        preshared_key,
        None,
        IndexTable::from_os_rng(),
        Arc::new(RateLimiter::new(&bob_public, 100)),
    );

    let initiation = alice
        .format_handshake_initiation(false)
        .unwrap_or_else(|| panic!("handshake initiation failed"));
    let TunnResult::WriteToNetwork(WgKind::HandshakeResp(response)) =
        bob.handle_incoming_packet(WgKind::HandshakeInit(initiation))
    else {
        panic!("Bob did not produce a handshake response");
    };
    let TunnResult::WriteToNetwork(WgKind::Data(keepalive)) =
        alice.handle_incoming_packet(WgKind::HandshakeResp(response))
    else {
        panic!("Alice did not complete the handshake");
    };
    assert!(matches!(
        bob.handle_incoming_packet(WgKind::Data(keepalive)),
        TunnResult::WriteToTunnel(packet) if packet.is_empty()
    ));
}
