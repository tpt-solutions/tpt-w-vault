# tpt-vault user guide

tpt-vault keeps your private files and notes in an encrypted vault. The vault is a folder on
your computer. Without your passphrase, the files in it look like scrambled data.

This guide describes the app as it works today. Features that are not finished are listed at the
end.

## Your privacy

- Nothing is uploaded. The vault never leaves your computer unless you copy its folder somewhere
  yourself.
- Encryption happens as the app writes, so note text is not stored as plain text on disk.

## Creating a vault

1. Open tpt-vault and choose **Create my vault**.
2. Choose an **empty** folder with **Browse…**, or type its path.
3. Choose a passphrase of at least 8 characters, and type it twice. Pick a sentence you will
   remember. Your passphrase is the everyday key, and it cannot be reset.
4. Save the **recovery code** that appears. It is shown only once. Write it down or print it,
   and keep it somewhere that is not on this computer. If you forget your passphrase, the
   recovery code is the only other way back into the vault.
5. Tick "I have stored my recovery code" and choose **Continue**.

## Unlocking

- Type the vault folder and your passphrase, then choose **Unlock**.
- If you have lost the passphrase, choose **Recovery code** and enter the code. You can type it
  with or without the hyphens.
- If Windows Hello is turned on for the vault, **Unlock with Windows Hello** appears. Your
  fingerprint or face confirms it.
- The **Recent vaults** list shows folders you opened on this computer. **Forget** removes the
  selected folder from that list. It does not touch the vault's files.

The recovery code guide is in [recovery-key.md](recovery-key.md). Installing is covered in
[install.md](install.md).

## Working with notes and folders

- **New note** creates a markdown file (`.md`). If you leave off `.md`, it is added.
- **New folder** creates a folder. Click a folder name to open it.
- **Rename** changes an item's name. You can also type a folder path, such as `work/plan.md`,
  to move the item there. Paths cannot contain empty parts or `..`.
- **Delete** asks for a second click before it removes anything.
- Notes save by themselves a moment after you stop typing. The status line next to the note name
  shows whether there are unsaved changes.
- **Preview** shows the note as formatted text. The toolbar inserts headings, lists, code blocks,
  links and tables.

Links appear as their text followed by the address in brackets. They are not clickable inside
the app, so the app never navigates away from your vault.

## Locking

- Choose **Lock** to lock the vault at once.
- The vault also locks when it has been idle for the number of minutes set in **Settings**
  (default 10). A warning appears shortly before it does. Moving the mouse or pressing a key
  cancels the warning.
- Closing the window, or quitting from the tray, locks the vault too.

## Settings

- **Auto-lock**: how many idle minutes pass before the vault locks (1 to 240).
- **Passphrase**: change your passphrase. Your recovery code keeps working.
- **Recovery code**: make a new recovery code. The old code stops working. Enter your passphrase
  to do this.
- **Windows Hello**: unlock with your fingerprint or face instead of typing the passphrase. Turning
  it on asks for your passphrase once.
- **Rebuild vault keys**: re-encrypts everything under new keys and makes a new recovery code. Use
  it if you think the keys were exposed. It copies every file, so it needs free disk space about
  twice the vault's size, and it can take a while.

## Using the vault as a drive

- **Windows**: the vault appears as a drive letter when you unlock it. It needs WinFsp, see
  [install.md](install.md). Without WinFsp the vault still opens in the app, but there is no drive.
- **Linux**: the vault appears in `~/tpt-vault` when you unlock it, and goes away when you lock it.

Lock the vault before you copy the vault folder somewhere else.

## Not available yet

- Drag-and-drop import from File Explorer.
- Renaming an entry in the recent vaults list. Use **Forget** to remove an entry instead.
- Linux desktop sessions have not been tested by hand yet (GNOME, KDE, X11 and Wayland).
