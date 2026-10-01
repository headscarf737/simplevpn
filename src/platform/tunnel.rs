// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::{IpAddr, SocketAddr};

use gotatun::{
    device::{DefaultDeviceTransports, Device, DeviceBuilder, Peer},
    tun::tun_async_device::TunDevice,
    x25519::{PublicKey, StaticSecret},
};
use tokio::net::lookup_host;

use crate::{AppError, Result, config::Profile, planner::ActiveProfile};

use super::verify;
use crate::supervisor::{
    operations::{Failure, OperationResult, TunnelParameters},
    state::FailureStage,
};

pub struct Tunnel {
    profile: Profile,
    interface: String,
    endpoints: Vec<SocketAddr>,
    device: Option<Device<DefaultDeviceTransports>>,
}

impl Tunnel {
    pub async fn resolve(profile: Profile) -> OperationResult<TunnelParameters> {
        let mut endpoints = Vec::with_capacity(profile.peers.len());
        for peer in &profile.peers {
            endpoints.push(
                resolve_endpoint(&peer.endpoint)
                    .await
                    .map_err(Failure::at(FailureStage::Interface))?,
            );
        }

        Ok(TunnelParameters { profile, endpoints })
    }

    pub async fn start(
        parameters: TunnelParameters,
        pending_interfaces: &mut Vec<String>,
    ) -> OperationResult<Self> {
        let TunnelParameters { profile, endpoints } = parameters;
        tracing::info!(profile = %profile.name, "starting tunnel");

        let tun = TunDevice::from_name("utun")
            .map_err(|error| AppError::Platform(format!("cannot create GotaTun utun: {error}")))
            .map_err(Failure::at(FailureStage::Interface))?;
        let interface = tun
            .name()
            .map_err(|error| {
                AppError::Platform(format!("cannot obtain GotaTun interface name: {error}"))
            })
            .map_err(Failure::at(FailureStage::Interface))?;
        tracing::info!(%interface, "configuring tunnel interface");
        if let Err(error) = configure_interface(&interface, &profile).await {
            drop(tun);
            return match verify::verify_interface_removed(&interface).await {
                Ok(()) => Err(Failure::new(FailureStage::Interface, error)),
                Err(cleanup_error) => {
                    pending_interfaces.push(interface.clone());
                    Err(Failure::new(
                        FailureStage::Cleanup,
                        AppError::Runtime(format!(
                            "{error}; interface cleanup also failed: {cleanup_error}"
                        )),
                    ))
                }
            };
        }

        let mut peers = Vec::with_capacity(profile.peers.len());
        for (peer, endpoint) in profile.peers.iter().zip(&endpoints) {
            let mut gotatun_peer = Peer::new(PublicKey::from(*peer.public_key.as_bytes()))
                .with_endpoint(*endpoint)
                .with_allowed_ips(peer.allowed_ips.iter().copied());
            gotatun_peer.preshared_key = peer.preshared_key.as_ref().map(|key| *key.expose());
            gotatun_peer.keepalive = peer.persistent_keepalive;
            peers.push(gotatun_peer);
        }

        tracing::info!(%interface, "starting WireGuard device");
        let device = DeviceBuilder::new()
            .with_private_key(StaticSecret::from(*profile.interface.private_key.expose()))
            .with_peers(peers)
            .with_listen_port(profile.interface.listen_port.unwrap_or(0))
            .with_default_udp()
            .udp_recv_buffer_size(7 * 1024 * 1024)
            .udp_send_buffer_size(7 * 1024 * 1024)
            .with_ip(tun)
            .build()
            .await;
        let device = match device {
            Ok(device) => device,
            Err(error) => {
                let error = AppError::Runtime(format!("cannot start GotaTun device: {error}"));
                return match verify::verify_interface_removed(&interface).await {
                    Ok(()) => Err(Failure::new(FailureStage::Interface, error)),
                    Err(cleanup_error) => {
                        pending_interfaces.push(interface.clone());
                        Err(Failure::new(
                            FailureStage::Cleanup,
                            AppError::Runtime(format!(
                                "{error}; interface cleanup also failed: {cleanup_error}"
                            )),
                        ))
                    }
                };
            }
        };

        Ok(Self {
            profile,
            interface,
            endpoints,
            device: Some(device),
        })
    }

    #[must_use]
    pub fn active_profile(&self) -> ActiveProfile {
        ActiveProfile {
            name: self.profile.name.clone(),
            priority: self.profile.priority,
            dns_priority: self.profile.dns_priority(),
            interface: self.interface.clone(),
            interface_addresses: self.profile.interface.addresses.clone(),
            allowed_routes: self.profile.allowed_routes().collect(),
            endpoints: self.endpoints.clone(),
            dns_servers: self
                .profile
                .dns
                .as_ref()
                .map_or_else(Vec::new, |dns| dns.servers.clone()),
            dns_search_domains: self
                .profile
                .dns
                .as_ref()
                .map_or_else(Vec::new, |dns| dns.search_domains.clone()),
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        if let Some(device) = self.device.take() {
            device.stop().await;
        }
        verify::verify_interface_removed(&self.interface).await
    }
}

async fn resolve_endpoint(endpoint: &crate::config::Endpoint) -> Result<SocketAddr> {
    let authority = endpoint.display_authority();
    let mut addresses = lookup_host((endpoint.host(), endpoint.port()))
        .await
        .map_err(|error| {
            AppError::Runtime(format!("cannot resolve endpoint {authority}: {error}"))
        })?;
    addresses
        .next()
        .ok_or_else(|| AppError::Runtime(format!("endpoint {authority} resolved to no addresses")))
}

async fn configure_interface(interface: &str, profile: &Profile) -> Result<()> {
    let mut first_ipv4 = true;
    for network in &profile.interface.addresses {
        let mut arguments = vec![interface.to_owned()];
        match network.ip() {
            IpAddr::V4(address) => {
                arguments.extend([
                    "inet".to_owned(),
                    address.to_string(),
                    address.to_string(),
                    "netmask".to_owned(),
                    ipv4_netmask(network.prefix()).to_string(),
                ]);
                if !first_ipv4 {
                    arguments.push("alias".to_owned());
                }
                first_ipv4 = false;
            }
            IpAddr::V6(address) => arguments.extend([
                "inet6".to_owned(),
                format!("{address}/{}", network.prefix()),
                "alias".to_owned(),
            ]),
        }
        run_ifconfig(&arguments).await?;
    }
    let mut final_arguments = vec![interface.to_owned()];
    if let Some(mtu) = profile.interface.mtu {
        final_arguments.extend(["mtu".to_owned(), mtu.to_string()]);
    }
    final_arguments.push("up".to_owned());
    run_ifconfig(&final_arguments).await?;
    verify::verify_interface(
        interface,
        &profile.interface.addresses,
        profile.interface.mtu,
    )
    .await
}

async fn run_ifconfig(arguments: &[String]) -> Result<()> {
    let output = super::command::ifconfig(arguments).await?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::Platform(format!(
            "ifconfig failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn ipv4_netmask(prefix: u8) -> std::net::Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    std::net::Ipv4Addr::from(mask)
}
