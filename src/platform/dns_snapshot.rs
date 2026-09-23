// SPDX-License-Identifier: GPL-3.0-or-later

use std::{collections::HashSet, ffi::c_void, net::IpAddr};

use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::{CFType, TCFType, ToVoid},
        dictionary::{CFDictionary, CFMutableDictionary},
        number::CFNumber,
        propertylist::CFPropertyList,
        string::CFString,
    },
    dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder},
    sys::schema_definitions::{
        kSCPropNetDNSDomainName, kSCPropNetDNSOptions, kSCPropNetDNSSearchDomains,
        kSCPropNetDNSSearchOrder, kSCPropNetDNSServerAddresses, kSCPropNetDNSServerPort,
        kSCPropNetDNSServerTimeout, kSCPropNetDNSSortList, kSCPropNetDNSSupplementalMatchDomains,
        kSCPropNetDNSSupplementalMatchOrders,
    },
};

use crate::{
    AppError, Result,
    journal::{DnsServiceSnapshot, DnsSnapshot},
};

const STATE_PATTERN: &str = "State:/Network/Service/.*/DNS";
const SETUP_PATTERN: &str = "Setup:/Network/Service/.*/DNS";

pub fn capture() -> Result<DnsSnapshot> {
    let store = store("simplevpn-recovery-capture")?;
    let mut paths = HashSet::new();
    if let Some(keys) = store.get_keys(STATE_PATTERN) {
        for key in keys.iter() {
            let state = key.to_string();
            paths.insert(state.clone());
            paths.insert(state.replacen("State:/", "Setup:/", 1));
        }
    }
    if let Some(keys) = store.get_keys(SETUP_PATTERN) {
        paths.extend(keys.iter().map(|key| key.to_string()));
    }
    let mut paths: Vec<_> = paths.into_iter().collect();
    paths.sort();
    let services = paths
        .into_iter()
        .map(|path| snapshot_service(&store, path))
        .collect();
    Ok(DnsSnapshot { services })
}

pub fn restore(snapshot: &DnsSnapshot) -> Result<()> {
    let store = store("simplevpn-recovery-restore")?;
    for service in &snapshot.services {
        if !service.existed {
            if !store.remove(CFString::new(&service.path))
                && store.get(CFString::new(&service.path)).is_some()
            {
                return Err(AppError::Runtime(format!(
                    "cannot remove stale DNS state {}",
                    service.path
                )));
            }
            continue;
        }
        let dictionary = build_dictionary(service);
        if !store.set(CFString::new(&service.path), dictionary) {
            return Err(AppError::Runtime(format!(
                "cannot restore DNS state {}",
                service.path
            )));
        }
    }
    Ok(())
}

pub fn verify_restored(expected: &DnsSnapshot) -> Result<()> {
    let store = store("simplevpn-recovery-verify")?;
    for service in &expected.services {
        let actual = snapshot_service(&store, service.path.clone());
        if actual != *service {
            return Err(verification_error(format!(
                "DNS state {} does not match the recovery snapshot",
                service.path
            )));
        }
    }
    Ok(())
}

pub fn apply_search_domains(search_domains: &[String]) -> Result<()> {
    let store = store("simplevpn-search-domains")?;
    let snapshot = capture()?;
    for service in snapshot.services.iter().filter(|service| service.existed) {
        let path = CFString::new(&service.path);
        let dictionary = store
            .get(path.clone())
            .and_then(CFPropertyList::downcast_into::<CFDictionary>)
            .ok_or_else(|| {
                AppError::Runtime(format!(
                    "cannot load DNS state {} while applying search domains",
                    service.path
                ))
            })?;
        let mut dictionary = CFMutableDictionary::from(&dictionary);
        let key = unsafe { kSCPropNetDNSSearchDomains }.cast();
        dictionary.remove(key);
        add_strings(&mut dictionary, key, search_domains);
        if !store.set(path, dictionary.to_immutable()) {
            return Err(AppError::Runtime(format!(
                "cannot apply DNS search domains to {}",
                service.path
            )));
        }
    }
    Ok(())
}

pub fn verify_config(
    expected_servers: &[IpAddr],
    expected_search_domains: &[String],
) -> Result<()> {
    let snapshot = capture()?;
    let expected: HashSet<_> = expected_servers.iter().copied().collect();
    let mut verified = 0_usize;
    for service in snapshot.services.iter().filter(|service| service.existed) {
        let actual: HashSet<IpAddr> = service
            .server_addresses
            .iter()
            .map(|server| {
                server.parse().map_err(|error| {
                    verification_error(format!(
                        "DNS state {} contains invalid server {server}: {error}",
                        service.path
                    ))
                })
            })
            .collect::<Result<_>>()?;
        if actual != expected {
            return Err(verification_error(format!(
                "DNS state {} contains {actual:?}, expected {expected:?}",
                service.path
            )));
        }
        if service.search_domains != expected_search_domains {
            return Err(verification_error(format!(
                "DNS state {} contains search domains {:?}, expected {:?}",
                service.path, service.search_domains, expected_search_domains
            )));
        }
        verified += 1;
    }
    if verified == 0 {
        return Err(verification_error(
            "no macOS network service exposes DNS state after configuration",
        ));
    }
    Ok(())
}

fn store(name: &str) -> Result<SCDynamicStore> {
    SCDynamicStoreBuilder::new(name).build().ok_or_else(|| {
        AppError::Platform("cannot open SystemConfiguration dynamic store".to_owned())
    })
}

fn verification_error(message: impl Into<String>) -> AppError {
    AppError::Runtime(format!(
        "system write verification failed: {}",
        message.into()
    ))
}

fn snapshot_service(store: &SCDynamicStore, path: String) -> DnsServiceSnapshot {
    let dictionary = store
        .get(CFString::new(&path))
        .and_then(CFPropertyList::downcast_into::<CFDictionary>);
    let Some(dictionary) = dictionary else {
        return DnsServiceSnapshot {
            path,
            existed: false,
            server_addresses: Vec::new(),
            search_domains: Vec::new(),
            domain_name: None,
            options: None,
            server_port: None,
            search_order: None,
            server_timeout: None,
            sort_list: Vec::new(),
            supplemental_match_domains: Vec::new(),
            supplemental_match_orders: Vec::new(),
        };
    };
    DnsServiceSnapshot {
        path,
        existed: true,
        server_addresses: strings(&dictionary, unsafe { kSCPropNetDNSServerAddresses }.cast()),
        search_domains: strings(&dictionary, unsafe { kSCPropNetDNSSearchDomains }.cast()),
        domain_name: string(&dictionary, unsafe { kSCPropNetDNSDomainName }.cast()),
        options: string(&dictionary, unsafe { kSCPropNetDNSOptions }.cast()),
        server_port: number(&dictionary, unsafe { kSCPropNetDNSServerPort }.cast())
            .and_then(|value| u16::try_from(value).ok()),
        search_order: number(&dictionary, unsafe { kSCPropNetDNSSearchOrder }.cast()),
        server_timeout: number(&dictionary, unsafe { kSCPropNetDNSServerTimeout }.cast()),
        sort_list: strings(&dictionary, unsafe { kSCPropNetDNSSortList }.cast()),
        supplemental_match_domains: strings(&dictionary, unsafe {
            kSCPropNetDNSSupplementalMatchDomains.cast()
        }),
        supplemental_match_orders: numbers(&dictionary, unsafe {
            kSCPropNetDNSSupplementalMatchOrders.cast()
        }),
    }
}

fn build_dictionary(service: &DnsServiceSnapshot) -> CFDictionary {
    let mut dictionary = CFMutableDictionary::new();
    add_strings(
        &mut dictionary,
        unsafe { kSCPropNetDNSServerAddresses }.cast(),
        &service.server_addresses,
    );
    add_strings(
        &mut dictionary,
        unsafe { kSCPropNetDNSSearchDomains }.cast(),
        &service.search_domains,
    );
    add_string(
        &mut dictionary,
        unsafe { kSCPropNetDNSDomainName }.cast(),
        service.domain_name.as_deref(),
    );
    add_string(
        &mut dictionary,
        unsafe { kSCPropNetDNSOptions }.cast(),
        service.options.as_deref(),
    );
    add_number(
        &mut dictionary,
        unsafe { kSCPropNetDNSServerPort }.cast(),
        service.server_port.map(i32::from),
    );
    add_number(
        &mut dictionary,
        unsafe { kSCPropNetDNSSearchOrder }.cast(),
        service.search_order,
    );
    add_number(
        &mut dictionary,
        unsafe { kSCPropNetDNSServerTimeout }.cast(),
        service.server_timeout,
    );
    add_strings(
        &mut dictionary,
        unsafe { kSCPropNetDNSSortList }.cast(),
        &service.sort_list,
    );
    add_strings(
        &mut dictionary,
        unsafe { kSCPropNetDNSSupplementalMatchDomains }.cast(),
        &service.supplemental_match_domains,
    );
    add_numbers(
        &mut dictionary,
        unsafe { kSCPropNetDNSSupplementalMatchOrders }.cast(),
        &service.supplemental_match_orders,
    );
    dictionary.to_immutable()
}

fn value(dictionary: &CFDictionary, key: *const c_void) -> Option<CFType> {
    dictionary
        .find(key)
        // SAFETY: values returned by `CFDictionary::find` are valid retained CF objects.
        .map(|pointer| unsafe { CFType::wrap_under_get_rule(*pointer) })
}

fn strings(dictionary: &CFDictionary, key: *const c_void) -> Vec<String> {
    value(dictionary, key)
        .and_then(|value| value.downcast::<CFArray>())
        .map(|array| {
            array
                .iter()
                // SAFETY: elements of the live CFArray are valid CF objects.
                .filter_map(|pointer| {
                    unsafe { CFType::wrap_under_get_rule(*pointer) }.downcast::<CFString>()
                })
                .map(|value| value.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn numbers(dictionary: &CFDictionary, key: *const c_void) -> Vec<i32> {
    value(dictionary, key)
        .and_then(|value| value.downcast::<CFArray>())
        .map(|array| {
            array
                .iter()
                // SAFETY: elements of the live CFArray are valid CF objects.
                .filter_map(|pointer| {
                    unsafe { CFType::wrap_under_get_rule(*pointer) }.downcast::<CFNumber>()
                })
                .filter_map(|value| value.to_i32())
                .collect()
        })
        .unwrap_or_default()
}

fn string(dictionary: &CFDictionary, key: *const c_void) -> Option<String> {
    value(dictionary, key)
        .and_then(|value| value.downcast::<CFString>())
        .map(|value| value.to_string())
}

fn number(dictionary: &CFDictionary, key: *const c_void) -> Option<i32> {
    value(dictionary, key)
        .and_then(|value| value.downcast::<CFNumber>())
        .and_then(|value| value.to_i32())
}

fn add_strings(dictionary: &mut CFMutableDictionary, key: *const c_void, values: &[String]) {
    if values.is_empty() {
        return;
    }
    let values: Vec<_> = values.iter().map(|value| CFString::new(value)).collect();
    let array = CFArray::from_CFTypes(&values).into_untyped();
    dictionary.add(&key, &array.to_void());
}

fn add_numbers(dictionary: &mut CFMutableDictionary, key: *const c_void, values: &[i32]) {
    if values.is_empty() {
        return;
    }
    let values: Vec<_> = values.iter().copied().map(CFNumber::from).collect();
    let array = CFArray::from_CFTypes(&values).into_untyped();
    dictionary.add(&key, &array.to_void());
}

fn add_string(dictionary: &mut CFMutableDictionary, key: *const c_void, value: Option<&str>) {
    if let Some(value) = value {
        dictionary.add(&key, &CFString::new(value).to_void());
    }
}

fn add_number(dictionary: &mut CFMutableDictionary, key: *const c_void, value: Option<i32>) {
    if let Some(value) = value {
        dictionary.add(&key, &CFNumber::from(value).to_void());
    }
}
