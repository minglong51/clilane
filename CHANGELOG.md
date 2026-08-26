# Changelog

## [0.8.1] - 2026-08-25

### Fixed

- `clilane hub` now returns control cleanly when its switcher popup closes, including when launched from `c` or `cdev` tmux panes.
- Stale popup processes can no longer detach a client or overwrite a newer switcher session.
- Running `clilane hub` inside CLI Lane now reports the same-server conflict instead of recursively attaching tmux.

### Changed

- The hidden hub backing pane now uses an inert standby screen instead of a login shell.
