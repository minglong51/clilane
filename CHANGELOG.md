# Changelog

## [Unreleased]

### Fixed

- `Left` and a bare `Esc` in the switcher no longer detach the client: `Left` only moves the composer cursor, and `Esc` clears the composer, returns to the job the switcher was opened from, or leaves the switcher when there is no job to return to.
- Unrecognised key sequences such as `Delete`, `Home`, `PageUp`, and `Ctrl-Left` are consumed whole instead of leaking stray `~` or `;5D` characters into the composer.

### Changed

- `Ctrl-C` clears the composer and, pressed twice within 2 seconds on an empty composer, leaves the switcher; `Ctrl-D` twice does the same. `Ctrl-Q` still leaves immediately. Every job keeps running.

## [0.8.1] - 2026-08-25

### Fixed

- `clilane hub` now returns control cleanly when its switcher popup closes, including when launched from `c` or `cdev` tmux panes.
- Stale popup processes can no longer detach a client or overwrite a newer switcher session.
- Running `clilane hub` inside CLI Lane now reports the same-server conflict instead of recursively attaching tmux.

### Changed

- The hidden hub backing pane now uses an inert standby screen instead of a login shell.
