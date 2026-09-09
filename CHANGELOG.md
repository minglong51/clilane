# Changelog

## [Unreleased]

### Added

- `Ctrl-R` in the switcher resumes a finished job: the same command relaunches in the same directory under the same name, with `--continue` for Claude and Kimi and `resume --last` for Codex, and the previous log becomes the new job's `.previous` log.
- `Enter` on a finished job now opens its peek instead of landing on a dead pane; `Right` still opens the pane for scrollback.

### Changed

- The documented tmux minimum is now 3.6. tmux 3.4 and 3.5 servers can crash while the switcher opens and closes its popup, ending every lane on that server; `run` still refuses only releases older than 3.3.

## [0.10.0] - 2026-09-07

### Added

- `Space` in the switcher peeks at the selected job's latest terminal output without opening it, and turns the composer into a reply composer for that job; `Enter` delivers the message through the same path as `clilane send --enter`. `Space` or `Esc` closes the peek.
- `Ctrl-X` in the switcher stops the selected running job or removes a finished one. It asks for a second press within 2 seconds, and any other key cancels.

## [0.9.0] - 2026-08-31

### Fixed

- `Left` in the switcher no longer detaches the client; it only moves the composer cursor. A bare `Esc` clears the composer, returns to the job the switcher was opened from, and detaches only when there is no job to return to.
- Unrecognised key sequences such as `Delete`, `Home`, `PageUp`, and `Ctrl-Left` are consumed whole instead of leaking stray `~` or `;5D` characters into the composer.
- `killpg` returning `EPERM` for a reported provider process group is treated as the group having exited, since a recycled group id no longer names a group the probe owns; this removes a macOS CI flake in the collector-cleanup tests.

### Changed

- `Ctrl-C` and `Ctrl-D` clear the composer; on an empty composer, the same key pressed twice within 2 seconds leaves the switcher. `Ctrl-Q` still leaves immediately. Every job keeps running.

## [0.8.1] - 2026-08-25

### Fixed

- `clilane hub` now returns control cleanly when its switcher popup closes, including when launched from `c` or `cdev` tmux panes.
- Stale popup processes can no longer detach a client or overwrite a newer switcher session.
- Running `clilane hub` inside CLI Lane now reports the same-server conflict instead of recursively attaching tmux.

### Changed

- The hidden hub backing pane now uses an inert standby screen instead of a login shell.
