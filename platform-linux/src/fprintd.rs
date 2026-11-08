// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Fingerprint consent via fprintd (`net.reactivated.Fprint`) on the system bus.
//!
//! The flow is: claim the default reader, start verification for any enrolled finger, wait for
//! a final `VerifyStatus` signal, then stop and release the reader. Availability means fprintd
//! answers and has a default device.

use tpt_vault_core::{ConsentGate, Result, VaultError};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

const SERVICE: &str = "net.reactivated.Fprint";
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const MANAGER_IFACE: &str = "net.reactivated.Fprint.Manager";
const DEVICE_IFACE: &str = "net.reactivated.Fprint.Device";

/// Fingerprint reader as a consent gate, using the system bus.
#[derive(Debug, Default, Clone, Copy)]
pub struct FprintGate;

fn bus_err(context: &'static str) -> impl FnOnce(zbus::Error) -> VaultError {
    move |e| VaultError::Platform(format!("{context}: {e}"))
}

/// Current login name, used when claiming the reader. Falls back to an empty name, which
/// fprintd resolves to the calling user.
fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default()
}

/// Maps a `VerifyStatus` result string to the outcome of one step. `Some(true)` means matched,
/// `Some(false)` means finished without a match, and `None` means keep waiting (a retry).
fn outcome(status: &str) -> Option<bool> {
    match status {
        "verify-match" => Some(true),
        "verify-no-match" | "verify-disconnected" | "verify-unknown-error" => Some(false),
        _ => None,
    }
}

impl FprintGate {
    fn default_device(conn: &Connection) -> Result<OwnedObjectPath> {
        let manager = Proxy::new(conn, SERVICE, MANAGER_PATH, MANAGER_IFACE)
            .map_err(bus_err("fprintd manager"))?;
        manager
            .call("GetDefaultDevice", &())
            .map_err(bus_err("finding a fingerprint reader"))
    }
}

impl ConsentGate for FprintGate {
    fn is_available(&self) -> bool {
        let Ok(conn) = Connection::system() else {
            return false;
        };
        Self::default_device(&conn).is_ok()
    }

    fn verify(&self, _prompt: &str) -> Result<bool> {
        let conn = Connection::system().map_err(bus_err("system bus"))?;
        let device_path = Self::default_device(&conn)?;
        let device = Proxy::new(&conn, SERVICE, device_path.as_ref(), DEVICE_IFACE)
            .map_err(bus_err("fingerprint reader"))?;

        device
            .call::<_, _, ()>("Claim", &(current_user()))
            .map_err(bus_err("claiming the fingerprint reader"))?;

        // Run the scan and wait for the result. The reader is always released afterwards.
        let result = (|| -> Result<bool> {
            // Subscribe before starting, so the final status cannot be missed.
            let signals = device
                .receive_signal("VerifyStatus")
                .map_err(bus_err("listening for fingerprint results"))?;
            device
                .call::<_, _, ()>("VerifyStart", &("any"))
                .map_err(bus_err("starting fingerprint verification"))?;
            for msg in signals {
                let (status, done): (String, bool) = msg
                    .body()
                    .deserialize()
                    .map_err(bus_err("reading fingerprint result"))?;
                if let Some(matched) = outcome(&status) {
                    return Ok(matched);
                }
                if done {
                    return Ok(false);
                }
            }
            Ok(false)
        })();

        let _ = device.call::<_, _, ()>("VerifyStop", &());
        let _ = device.call::<_, _, ()>("Release", &());
        result
    }
}
