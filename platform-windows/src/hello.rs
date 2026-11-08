// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Windows Hello consent via `UserConsentVerifier`.
//!
//! The prompt proves a live user is present and approves the unlock. It does not itself
//! decrypt anything: the key is released only after `verify` returns true, and the key is
//! DPAPI-protected at rest.
//!
//! `verify` blocks until the user responds. Call it from a background thread, never from the UI
//! thread, which the prompt may need in order to draw.

use tpt_vault_core::{ConsentGate, Result, VaultError};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows::core::{HSTRING, factory};

/// Windows Hello as a consent gate. Optionally anchored to a window so the prompt appears over
/// the app rather than floating free.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsHello {
    /// Raw window handle of the app window, if known.
    hwnd: Option<isize>,
}

impl WindowsHello {
    /// Anchors prompts to an application window.
    pub fn for_window(hwnd: isize) -> Self {
        WindowsHello { hwnd: Some(hwnd) }
    }

    fn wait<T: windows::core::RuntimeType>(
        op: windows_future::IAsyncOperation<T>,
    ) -> windows::core::Result<T> {
        op.get()
    }
}

impl ConsentGate for WindowsHello {
    fn is_available(&self) -> bool {
        let Ok(op) = UserConsentVerifier::CheckAvailabilityAsync() else {
            return false;
        };
        matches!(
            Self::wait(op),
            Ok(UserConsentVerifierAvailability::Available)
        )
    }

    fn verify(&self, prompt: &str) -> Result<bool> {
        let message = HSTRING::from(prompt);
        let result = match self.hwnd {
            Some(raw) => {
                let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
                    .map_err(|e| VaultError::Platform(format!("Windows Hello interop: {e}")))?;
                // SAFETY: the window handle is supplied by the app, which owns the window and
                // keeps it alive for the duration of the prompt.
                let op = unsafe {
                    interop.RequestVerificationForWindowAsync::<
                        windows_future::IAsyncOperation<UserConsentVerificationResult>,
                    >(HWND(raw as *mut _), &message)
                }
                .map_err(|e| VaultError::Platform(format!("Windows Hello prompt: {e}")))?;
                Self::wait(op)
            }
            None => {
                let op = UserConsentVerifier::RequestVerificationAsync(&message)
                    .map_err(|e| VaultError::Platform(format!("Windows Hello prompt: {e}")))?;
                Self::wait(op)
            }
        }
        .map_err(|e| VaultError::Platform(format!("Windows Hello prompt: {e}")))?;
        Ok(result == UserConsentVerificationResult::Verified)
    }
}
