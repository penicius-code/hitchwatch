# Changelog

## Unreleased (changes made for publication, 2026-11-24)
- The game folder, process name and output folder are read from the environment variables `HITCHWATCH_GAME_DIR`, `HITCHWATCH_GAME_EXE` and `HITCHWATCH_OUT`. Captures go to `captures\` next to the script by default.
- No change to recording or analysis. The self-test passes.

## 1.0.0 with fixes - 2026-11-22
### Fixed
- Recording failed with "Invalid temporary trace directory (0xc5586004)" when the capture folder was reached through a directory junction. The folder is resolved to its real path before it is passed to `wpr`.
### Added
- `record --frames-only`: frame times only, without the kernel trace.
- `framepacing.py`: a frame pacing report from frame times alone (displayed against game-frame pacing, short/long alternation, CPU- or GPU-bound, spike spacing).
### Known problem
- PresentMon recorded no presents for the game in four runs on this date, so these features could not be confirmed on the current setup. The last working frame-time capture is from 2026-11-09.

## 1.0.0 - 2026-11-08
- First version: `record`, `analyze`, `compare`; own `.etl` reader; per-hitch attribution to modules, threads, file writes, other processes and drivers; detection of sources with a fixed rhythm; report in Markdown and CSV; synthetic self-test.
