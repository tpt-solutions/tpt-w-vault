// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Secret Service (`org.freedesktop.secrets`) as a [`SecretStore`]: GNOME Keyring, KWallet
//! (via its Secret Service bridge) and compatible providers.
//!
//! Each platform key is an item in the default collection, found by the attributes
//! `application=tpt-vault` and `name=<entry name>`. The keyring encrypts items at rest with
//! the user's login secret, so the blob is stored as-is.
//!
//! Interactive unlock prompts are not supported. If the collection is locked, or creating or
//! reading an item needs a prompt, the call fails and the caller falls back to passphrase
//! unlock.

use std::collections::HashMap;

use tpt_vault_core::{Result, SecretStore, VaultError};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

const SERVICE: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
const APPLICATION: &str = "tpt-vault";

/// The `(oayays)` secret structure from the Secret Service specification.
type SecretStruct = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// Connection to the session bus's Secret Service provider.
pub struct SecretService {
    conn: Connection,
}

fn platform<E: std::fmt::Display>(context: &'static str) -> impl FnOnce(E) -> VaultError {
    move |e| VaultError::Platform(format!("{context}: {e}"))
}

impl SecretService {
    /// Connects to the session bus. Fails when there is no session bus, which is the normal
    /// case on a headless or non-desktop system.
    pub fn connect() -> Result<Self> {
        let conn = Connection::session().map_err(platform("session bus"))?;
        Ok(SecretService { conn })
    }

    /// Whether a Secret Service provider currently owns its bus name. Used to decide whether to
    /// offer platform unlock at all.
    pub fn provider_present() -> bool {
        let Ok(conn) = Connection::session() else {
            return false;
        };
        let Ok(bus) = Proxy::new(
            &conn,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        ) else {
            return false;
        };
        let names: std::result::Result<Vec<String>, _> = bus.call("ListNames", &());
        names.is_ok_and(|names| names.iter().any(|n| n == SERVICE))
    }

    fn service(&self) -> Result<Proxy<'_>> {
        Proxy::new(&self.conn, SERVICE, SERVICE_PATH, SERVICE_IFACE)
            .map_err(platform("Secret Service"))
    }

    /// Opens a plain (unencrypted-transport) session. The bus is local, and the keyring still
    /// encrypts items at rest.
    fn open_session(&self) -> Result<OwnedObjectPath> {
        let body = ("plain", Value::from(""));
        let (_output, session): (OwnedValue, OwnedObjectPath) = self
            .service()?
            .call("OpenSession", &body)
            .map_err(platform("opening Secret Service session"))?;
        Ok(session)
    }

    fn default_collection(&self) -> Result<OwnedObjectPath> {
        let alias: OwnedObjectPath = self
            .service()?
            .call("ReadAlias", &("default"))
            .map_err(platform("finding the default keyring"))?;
        if alias.as_str() == "/" {
            return Err(VaultError::Platform("no default keyring is set up".into()));
        }
        Ok(alias)
    }

    /// Items matching this entry's attributes: `(unlocked, locked)`.
    fn search(&self, name: &str) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let attrs: HashMap<&str, &str> = [("application", APPLICATION), ("name", name)]
            .into_iter()
            .collect();
        self.service()?
            .call("SearchItems", &(attrs))
            .map_err(platform("searching the keyring"))
    }

    fn item(&self, path: &OwnedObjectPath) -> Result<Proxy<'_>> {
        Proxy::new(&self.conn, SERVICE, path.clone().into_inner(), ITEM_IFACE)
            .map_err(platform("keyring item"))
    }
}

/// Reports whether a Secret Service method returned an interactive prompt. Prompts are not
/// supported, so the caller treats them as a failure.
fn no_prompt(prompt: &ObjectPath<'_>) -> Result<()> {
    if prompt.as_str() == "/" {
        Ok(())
    } else {
        Err(VaultError::Platform(
            "the keyring needs an interactive prompt, which tpt-vault cannot show here".into(),
        ))
    }
}

impl SecretStore for SecretService {
    fn put(&self, name: &str, blob: &[u8]) -> Result<()> {
        let session = self.open_session()?;
        let collection = self.default_collection()?;
        let attrs: HashMap<&str, &str> = [("application", APPLICATION), ("name", name)]
            .into_iter()
            .collect();
        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert("org.freedesktop.Secret.Item.Label", Value::from(name));
        properties.insert("org.freedesktop.Secret.Item.Attributes", Value::from(attrs));
        let secret: SecretStruct = (
            session,
            Vec::new(),
            blob.to_vec(),
            "application/octet-stream".into(),
        );

        let collection_proxy = Proxy::new(
            &self.conn,
            SERVICE,
            collection.as_ref(),
            "org.freedesktop.Secret.Collection",
        )
        .map_err(platform("keyring collection"))?;
        // replace = true overwrites an existing item with the same attributes.
        let (_item, prompt): (OwnedObjectPath, OwnedObjectPath) = collection_proxy
            .call("CreateItem", &(properties, secret, true))
            .map_err(platform("storing item in the keyring"))?;
        no_prompt(&prompt)
    }

    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let (unlocked, locked) = self.search(name)?;
        let Some(item) = unlocked.first() else {
            return if locked.is_empty() {
                Ok(None)
            } else {
                Err(VaultError::Platform("the keyring is locked".into()))
            };
        };
        let session = self.open_session()?;
        let secret: SecretStruct = self
            .item(item)?
            .call("GetSecret", &(session))
            .map_err(platform("reading item from the keyring"))?;
        Ok(Some(secret.2))
    }

    fn delete(&self, name: &str) -> Result<()> {
        let (unlocked, locked) = self.search(name)?;
        if unlocked.is_empty() && locked.is_empty() {
            return Ok(());
        }
        for item in unlocked.iter().chain(locked.iter()) {
            let prompt: OwnedObjectPath = self
                .item(item)?
                .call("Delete", &())
                .map_err(platform("deleting item from the keyring"))?;
            no_prompt(&prompt)?;
        }
        Ok(())
    }
}
