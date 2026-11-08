// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Recovery codes: a 256-bit secret, written on paper, that can unwrap the master key without
//! the passphrase or any platform unlock method.
//!
//! Display form: 55 Crockford base32 characters in groups of five, separated by `-`. The
//! payload is the 32-byte secret followed by a 2-byte SHA-256 checksum, so a mistyped
//! character is caught before any decryption is attempted.

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::keys::random_bytes;

/// Crockford base32: no I, L, O or U, so handwritten codes are harder to misread.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const SECRET_LEN: usize = 32;
const CHECKSUM_LEN: usize = 2;
const PAYLOAD_LEN: usize = SECRET_LEN + CHECKSUM_LEN; // 34 bytes = 272 bits
const CHAR_COUNT: usize = 55; // ceil(272 / 5), with 3 zero padding bits at the end
const GROUP: usize = 5;

/// A printable recovery code. Show it to the user once; it is not stored in the vault.
pub struct RecoveryCode(String);

impl RecoveryCode {
    /// The grouped display form, for printing or showing on screen.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

fn checksum(secret: &[u8; SECRET_LEN]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::digest(secret);
    [digest[0], digest[1]]
}

/// Generates a new secret and its display code. The caller derives the wrapping key from the
/// secret and should zeroize it afterwards.
pub(crate) fn generate() -> ([u8; SECRET_LEN], RecoveryCode) {
    let secret: [u8; SECRET_LEN] = random_bytes();
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..SECRET_LEN].copy_from_slice(&secret);
    payload[SECRET_LEN..].copy_from_slice(&checksum(&secret));
    let chars = encode_base32(&payload);
    payload.zeroize();
    (secret, RecoveryCode(group(&chars)))
}

/// Parses a code typed by the user. Tolerates case, spaces, dashes and the usual
/// look-alike substitutions (O for 0, I or L for 1).
pub(crate) fn parse(input: &str) -> Result<[u8; SECRET_LEN]> {
    let invalid = || VaultError::InvalidRecoveryCode;
    let mut normalized = String::with_capacity(CHAR_COUNT);
    for c in input.chars() {
        match c {
            ' ' | '\t' | '\r' | '\n' | '-' => {}
            _ => normalized.push(match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                other => other,
            }),
        }
    }
    if normalized.len() != CHAR_COUNT {
        return Err(invalid());
    }
    let mut payload = decode_base32(&normalized).ok_or_else(invalid)?;
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(&payload[..SECRET_LEN]);
    let ok = payload[SECRET_LEN..] == checksum(&secret);
    payload.zeroize();
    if !ok {
        secret.zeroize();
        return Err(invalid());
    }
    Ok(secret)
}

fn encode_base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes exactly [`PAYLOAD_LEN`] bytes. Returns `None` on any non-alphabet character, or if
/// the padding bits at the end are not zero.
fn decode_base32(chars: &str) -> Option<[u8; PAYLOAD_LEN]> {
    let mut out = [0u8; PAYLOAD_LEN];
    let mut written = 0usize;
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in chars.bytes() {
        let value = ALPHABET.iter().position(|&a| a == c)? as u32;
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if written >= PAYLOAD_LEN {
                return None;
            }
            out[written] = (acc >> bits) as u8;
            written += 1;
            acc &= (1 << bits) - 1;
        }
    }
    // 55 characters carry 275 bits: 272 for the payload and 3 zero padding bits.
    if written != PAYLOAD_LEN || acc != 0 {
        return None;
    }
    Some(out)
}

fn group(s: &str) -> String {
    s.as_bytes()
        .chunks(GROUP)
        .map(|c| std::str::from_utf8(c).expect("ASCII alphabet"))
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_code_parses_back_to_its_secret() {
        let (secret, code) = generate();
        assert_eq!(parse(code.as_str()).unwrap(), secret);
    }

    #[test]
    fn display_form_is_eleven_groups_of_five() {
        let (_, code) = generate();
        let groups: Vec<&str> = code.as_str().split('-').collect();
        assert_eq!(groups.len(), 11);
        assert!(groups.iter().all(|g| g.len() == GROUP));
    }

    #[test]
    fn tolerates_case_spacing_and_lookalikes() {
        let (secret, code) = generate();
        let mangled = code
            .as_str()
            .to_lowercase()
            .replace('-', "  ")
            .replace('0', "o")
            .replace('1', "l");
        assert_eq!(parse(&mangled).unwrap(), secret);
    }

    #[test]
    fn single_character_typo_is_rejected() {
        let (_, code) = generate();
        let mut chars: Vec<char> = code.as_str().chars().collect();
        // Change the first secret character to a different valid alphabet character.
        let i = chars.iter().position(|c| *c != '-').unwrap();
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typed: String = chars.into_iter().collect();
        assert!(matches!(
            parse(&typed),
            Err(VaultError::InvalidRecoveryCode)
        ));
    }

    #[test]
    fn wrong_length_and_bad_characters_are_rejected() {
        assert!(parse("").is_err());
        assert!(parse("ABCDE-FGHIJ").is_err());
        let (_, code) = generate();
        // The first character of a code is always a payload character, never a dash.
        // 'U' is excluded from Crockford base32, so this must be rejected.
        let bad = format!("U{}", &code.as_str()[1..]);
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn base32_round_trips_arbitrary_payloads() {
        for seed in 0u8..=255 {
            let payload: Vec<u8> = (0..PAYLOAD_LEN as u8)
                .map(|i| i.wrapping_mul(seed))
                .collect();
            let encoded = encode_base32(&payload);
            assert_eq!(encoded.len(), CHAR_COUNT);
            assert_eq!(&decode_base32(&encoded).unwrap()[..], &payload[..]);
        }
    }
}
