# HitchWatch

A Windows tool that records a short kernel trace next to frame times and names what was busy during each game stutter. Written for Cyberpunk 2077; the game folder and process name are settings.
Version 1.0.0 | Windows 10/11, Python 3.11 | Status: trace capture and analysis working; frame-time capture currently not working on the author's setup (see Known issues)

> Not affiliated with any game developer or publisher. No game files or third-party binaries are included. It never starts, stops or edits the game.

## The problem

"A stutter every 4 to 6 seconds" in a game with several hundred mods. Frame-time graphs show that it happens, not who causes it. Turning mods off one by one takes days.

## What I built

A recorder and analyser, about 2,600 lines of Python in four files. It records 60 seconds of Windows kernel trace and frame times on the same clock while you play, finds the frames that stalled, and charges each stall to whatever was busy only during the stalls:

- every native module in the game process, by code that ran and by presence on the call stack;
- what the game's main thread was doing: running which code, waiting on what and on whom, or starved of CPU;
- other game threads, files the game wrote (and which module wrote them), hard page faults;
- other processes, and driver interrupt time;
- every source that fires on a fixed rhythm, and whether that rhythm matches the stutter.

## How it works

- **Recording.** `wpr.exe`, which ships with Windows, runs the profile `hitchwatch.wprp`: CPU samples at 1 kHz with stacks, context switches and ready-thread events, DPC / ISR, file I/O with stacks on create / write / flush, hard faults. PresentMon records every present at the same time. Both use the QPC clock, so frames and trace events line up.
- **Parsing.** `etwfile.py` reads the `.etl` file through the Windows trace API with ctypes. No external tool is needed.
- **Hitch definition.** A present gap of at least max(2.5 x rolling median, median + 18 ms, 25 ms). All three numbers are options.
- **Attribution.** For each source: its cost inside hitch windows above its normal rate, the share of hitches where it was clearly above normal ("coverage"), and the share of random normal windows where it was too ("false"). A good suspect has high coverage and low false.
- **Names.** Module paths under the game folder are labelled by folder; if a mod manager's deployment file is present in the game folder, modules get the mod's name.
- **Self-test.** `selftest.py` feeds synthetic kernel events through the real collector, analysis and report: a planted plugin that runs 45 ms on the main thread every 5 seconds and writes a log file, plus an unrelated background process with a 2-second rhythm.

```text
hitchwatch.py          record / analyze / compare
etwfile.py             .etl reader (ctypes)
framepacing.py         frame pacing report from frame times alone
selftest.py            synthetic end-to-end test
hitchwatch.wprp        trace profile for wpr.exe
Start HitchWatch.bat   asks for admin once, then records
```

## Requirements

| Requirement | Version | Link |
|---|---|---|
| Windows | 10 or 11 (`wpr.exe` is included) | |
| Python | 3.11 used | [python.org](https://www.python.org/downloads/windows/) |
| psutil (Python package) | current | `pip install psutil` |
| PresentMon console | 2.x | [GameTechDev/PresentMon](https://github.com/GameTechDev/PresentMon) |
| Administrator rights | for recording only | The kernel trace needs them. Analysis does not. |

Nothing is bundled.

## Setup

Set two environment variables, or edit the two lines at the top of `hitchwatch.py`:

```text
HITCHWATCH_GAME_DIR   the game's install folder
HITCHWATCH_GAME_EXE   the process name (default Cyberpunk2077.exe)
HITCHWATCH_OUT        optional: where captures go (default: captures\ next to the script)
```

## Use

1. Start the game, load a save and go to where it stutters.
2. Switch out of the game and double-click `Start HitchWatch.bat`. Accept the administrator prompt.
3. Go back into the game within 10 seconds. One beep = recording started. Play normally for 60 seconds.
4. Two beeps = done. The trace is saved and analysed (1 to 3 minutes, at low priority).
5. The window prints the report path: `captures\<date_time>\REPORT.md`. All captures are listed in `captures\INDEX.md`.

```text
python -I -X utf8 hitchwatch.py record [--seconds 60] [--delay 10]     needs admin; the .bat does this
python -I -X utf8 hitchwatch.py analyze --latest                        re-analyse, no admin needed
python -I -X utf8 hitchwatch.py compare <capture A> <capture B>         before / after a change
python -I -X utf8 selftest.py                                           synthetic test, no admin, no game
```

## Reading the report

- **Verdict**: hitch count, size and rhythm; where the time went per hitch (main thread busy in a named module, busy in the game's own code, waiting, starved, or not the main thread at all); the top suspects; sources with a fixed rhythm.
- **Top suspects**: `+X ms per hitch`, `coverage`, `false` as described above.
- **Hitches table**: one row per hitch with main-thread run / wait / ready time, the code that ran extra, who woke the thread, any other process, the longest DPC and the file writes.
- **Every native module**: CPU per module over the whole capture.

## Uninstall

Delete the folder. Captures are inside it (`captures\`), or wherever `HITCHWATCH_OUT` points. Only the three newest trace files are kept; each is a few hundred MB.

## Status

| What | Result |
|---|---|
| Self-test | Passes (9 checks: 8 planted hitches found, 5-second rhythm, planted plugin as top suspect, its log write found, the script host's tick wrapper not blamed, unrelated 2-second process reported). Run from this repository on 2026-11-24. |
| Kernel trace capture and module analysis | Working. Last real capture: 2026-11-22. |
| Frame-time capture | Worked until 2026-11-09. Since then PresentMon records no presents for the game on the author's setup (see Known issues), so recent captures have module totals but no hitch windows. |

## Known issues

- **No frame times on the author's current setup.** Four PresentMon runs on 2026-11-22, with and without the kernel trace, wrote no frames for the game process. The suspected cause is a change in the display chain (upscaler / frame-generation layers) or another frame-capture service on the PC; it is not confirmed. Without frame times there are no hitch windows.
- Script hosts are one block: all scripts of an in-process Lua host show as that host's module plus JIT code. Game scripts compiled into the executable show as executable time; only hot code offsets are listed for comparing runs.
- 1 kHz sampling: hitches under about 10 ms are measured coarsely.
- The module-to-mod naming reads one mod manager's deployment file format. Without it, modules are labelled by folder.

## Engineering notes

**A failure of the tool itself.** After the capture folder was moved to another drive and reached through a directory junction, every recording failed with `wpr -start failed: Invalid temporary trace directory (0xc5586004)`. Nothing had changed in the code.

**Diagnosis.** The error names the temporary trace directory, and the failures began on the day the capture folder was moved behind a junction. `wpr` rejects a temporary-trace path that goes through a junction.

**Fix.** The recorder resolves the capture folder to its real path before handing it to `wpr`.

**What the tool did and did not find.** HitchWatch was built for one periodic stutter. Its module totals ruled suspects out (for example a render-graph plugin that looked heavy by inclusive time but had very little code of its own running: it only sat on the stack of the engine's render jobs). The stutter itself turned out to come from script work inside the game's Lua host, which this tool can only show as one block. That cause was found by moving halves of the mod set out and by stopping the Lua garbage collector with a small probe to measure the garbage rate.

**Rollback.** The tool changes nothing on the system. `wpr` sessions are stopped by the script; if a recording is interrupted, `wpr -cancel -instancename HitchWatch` ends the session.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Credits and licence

Uses `wpr.exe` (Windows) and PresentMon (Intel), neither included. Kernel event layouts follow the public x64 layouts.

MIT, see [LICENSE](LICENSE).

Built with AI assistance (Claude); designed, tested and maintained by me.
