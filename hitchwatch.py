"""HitchWatch 1.0.0 (Cyberslop, 2026-11-08): find what causes periodic frame hitches in Cyberpunk 2077.

Records a short system-wide kernel trace (wpr.exe, built into Windows) next to PresentMon frame times, both on the
same QPC clock, then charges every hitch to whatever was busy only during hitches:
  - native modules in the game process (RED4ext plugins, CET, ReShade / RenoDX / OptiScaler, DLSS, NVIDIA driver,
    overlays), exclusive (code that ran) and inclusive (on the call stack), mapped to Vortex mod names;
  - GameThread state: running, waiting (wait reason + the thread that woke it + what that thread ran), starved;
  - game threads, files the game wrote (with the module that wrote them), hard page faults;
  - other processes, driver DPC / ISR time;
  - sources that fire on a fixed rhythm (bursts every N s), matched against the hitch rhythm.
Limits: CET Lua shows as one block (cyber_engine_tweaks.asi + "no module" JIT code); redscript runs inside
Cyberpunk2077.exe, so pure script work shows as exe time on GameThread (hot exe offsets are listed for comparing runs).

Usage (set HITCHWATCH_GAME_DIR to your game folder first, see README):
  Start HitchWatch.bat                      one UAC prompt, waits for the game, 10 s countdown,
                                                                 records 60 s, analyses, prints the report path
  python -I -X utf8 hitchwatch.py record [--seconds 60] [--delay 10] [--no-analyze]   (admin)
  python -I -X utf8 hitchwatch.py analyze [--latest | FOLDER] [--min-gap-ms 25 ...]
  python -I -X utf8 hitchwatch.py compare FOLDER_A FOLDER_B
Output: captures\\<YYYY-MM-DD_HH-MM-SS>\\REPORT.md (+ hitches.csv, modules.csv, periodic.csv, summary.json,
frames.csv, trace.etl; the newest 3 trace.etl files are kept). Never starts, stops or edits the game.
"""
import argparse
import array
import bisect
import collections
import csv
import ctypes
import ctypes.wintypes as wt
import datetime as dt
import json
import os
import random
import re
import shutil
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # python -I does not add the script folder
import etwfile as E  # noqa: E402
from framepacing import frames_report  # noqa: E402

VERSION = "1.0.0"
GAME_DIR = Path(os.environ.get("HITCHWATCH_GAME_DIR", r"C:\Program Files (x86)\GOG Galaxy\Games\Cyberpunk 2077"))
GAME_EXE = os.environ.get("HITCHWATCH_GAME_EXE", "Cyberpunk2077.exe")
# Captures and reports go here. Override with the environment variable HITCHWATCH_OUT.
OUT = Path(os.environ.get("HITCHWATCH_OUT", str(HERE / "captures")))
WPRP = HERE / "hitchwatch.wprp"
INSTANCE = "HitchWatch"
PM_SESSION = "HitchWatchPM"
KEEP_TRACES = 3
PRESENTMON_CANDIDATES = [
    Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Packages"
    / "Intel.PresentMon.Console_Microsoft.Winget.Source_8wekyb3d8bbwe" / "presentmon.exe",
    Path(r"C:\Program Files\Intel\PresentMon\PresentMonCli\PresentMon.exe"),
]
KBASE = 0xFFFF800000000000
OWNER_CATS = ("mod", "overlay", "unknown")                      # can "own" engine work called from them
SUSPECT_CATS = ("mod", "overlay", "unknown", "driver", "other", "game")  # not the exe, not Windows

WAIT_REASONS = ["Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution", "Suspended", "UserRequest",
                "WrExecutive", "WrFreePage", "WrPageIn", "WrPoolAllocation", "WrDelayExecution", "WrSuspended",
                "WrUserRequest", "WrEventPair", "WrQueue", "WrLpcReceive", "WrLpcReply", "WrVirtualMemory",
                "WrPageOut", "WrRendezvous", "WrKeyedEvent", "WrTerminated", "WrProcessInSwap", "WrCpuRateControl",
                "WrCalloutStack", "WrKernel", "WrResource", "WrPushLock", "WrMutex", "WrQuantumEnd",
                "WrDispatchInt", "WrPreempted", "WrYieldExecution", "WrFastMutex", "WrGuardedMutex", "WrRundown",
                "WrAlertByThreadId", "WrDeferredPreempt", "WrPhysicalFault", "WrIoRing", "WrMdlCache"]
WAIT_HINT = {"WrAlertByThreadId": "user-mode lock / condition variable (job system, mutex, SRW lock)",
             "UserRequest": "WaitForSingleObject-style wait (event, fence, I/O)",
             "WrUserRequest": "WaitForSingleObject-style wait (event, fence, I/O)",
             "DelayExecution": "Sleep()", "WrDelayExecution": "Sleep()",
             "PageIn": "paging in memory (disk)", "WrPageIn": "paging in memory (disk)",
             "Executive": "kernel wait (I/O, driver)", "WrQueue": "worker queue / I/O completion port",
             "WrPushLock": "kernel lock", "WrResource": "kernel resource lock", "WrPreempted": "preempted",
             "WrDispatchInt": "preempted by the scheduler", "WrYieldExecution": "yield"}
# processes known for periodic sensor polling or frame-hooking overlays (name fragments, lower case)
KNOWN_POLLERS = ["hwinfo", "afterburner", "rtss", "icue", "armoury", "lightingservice", "nzxt", "signalrgb",
                 "openrgb", "wallpaper", "razer", "lghub", "steelseries", "corsair", "gpu-z", "hwmonitor", "aida",
                 "discord", "gameoverlayui", "nvidia overlay", "nvcontainer", "obs64", "medal", "gamebar",
                 "overwolf", "presentmon", "fpsmonitor", "msi center", "dragon center", "fancontrol", "argus",
                 "xtu", "ryzen master", "elgato", "streamdeck", "voicemeeter", "nahimic", "sonic studio",
                 "wemod", "logioptions", "everything", "onedrive", "dropbox", "googledrivefs", "searchindexer",
                 "msmpeng", "mbam", "avast", "avg", "kaspersky", "bdservice", "nvidia-smi"]
OVERLAY_DLLS = {"gameoverlayrenderer64.dll": "Steam overlay", "discordhook64.dll": "Discord overlay",
                "rtsshooks64.dll": "RivaTuner overlay", "graphics-hook64.dll": "OBS game capture",
                "nvspcap64.dll": "NVIDIA overlay / ShadowPlay", "medalhook64.dll": "Medal",
                "owclient.dll": "Overwolf", "xsplitgamesource64.dll": "XSplit", "fraps64.dll": "Fraps"}

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenThread.restype = wt.HANDLE
k32.OpenProcess.restype = wt.HANDLE


# ================================================================================================= small helpers
def log(msg):
    print(f"{dt.datetime.now():%H:%M:%S} {msg}", flush=True)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def qpc():
    c = ctypes.c_int64()
    k32.QueryPerformanceCounter(ctypes.byref(c))
    return c.value


def qpc_freq():
    f = ctypes.c_int64()
    k32.QueryPerformanceFrequency(ctypes.byref(f))
    return f.value


def filetime_now():
    ft = ctypes.c_uint64()
    k32.GetSystemTimePreciseAsFileTime(ctypes.byref(ft))
    return ft.value


def anchor():
    """(qpc, filetime, unix) read back to back."""
    a = qpc()
    f = filetime_now()
    b = qpc()
    return {"qpc": (a + b) // 2, "filetime": f, "unix": f / 1e7 - 11644473600.0}


def efficiency_cores():
    try:
        needed = wt.ULONG(0)
        k32.GetSystemCpuSetInformation(None, 0, ctypes.byref(needed), None, 0)
        buf = ctypes.create_string_buffer(needed.value)
        if not k32.GetSystemCpuSetInformation(buf, needed, ctypes.byref(needed), None, 0):
            return []
        raw, off, sets = buf.raw, 0, []
        while off + 24 <= needed.value:
            size = int.from_bytes(raw[off:off + 4], "little")
            if size <= 0:
                break
            if int.from_bytes(raw[off + 12:off + 14], "little") == 0:
                sets.append((raw[off + 14], raw[off + 18]))
            off += size
        classes = {e for _, e in sets}
        if len(classes) < 2:
            return []
        low = min(classes)
        return sorted(lp for lp, e in sets if e == low)
    except (OSError, AttributeError, ValueError):
        return []


def calm_self():
    """Below-normal priority on the E-cores, so the analysis never competes with the game."""
    try:
        import psutil
        p = psutil.Process()
        p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        ec = efficiency_cores()
        if ec:
            p.cpu_affinity(ec)
    except Exception:
        pass


def beep(freq=1000, ms=150):
    try:
        import winsound
        winsound.Beep(freq, ms)
    except Exception:
        pass


def find_presentmon():
    for p in PRESENTMON_CANDIDATES:
        if p.is_file():
            return p
    w = shutil.which("presentmon") or shutil.which("PresentMon")
    return Path(w) if w else None


def thread_info(tid):
    """(name, win32 start address) of a live thread."""
    name, start = "", 0
    h = k32.OpenThread(0x0800 | 0x0040, False, tid)  # QUERY_LIMITED | QUERY_INFORMATION
    if not h:
        h = k32.OpenThread(0x0800, False, tid)
    if not h:
        return name, start
    try:
        p = ctypes.c_wchar_p()
        try:
            if k32.GetThreadDescription(wt.HANDLE(h), ctypes.byref(p)) >= 0 and p.value:
                name = p.value
                k32.LocalFree(p)
        except (OSError, AttributeError):
            pass
        addr = ctypes.c_uint64()
        try:
            st = ctypes.WinDLL("ntdll").NtQueryInformationThread(wt.HANDLE(h), 9, ctypes.byref(addr), 8, None)
            if st == 0:
                start = addr.value
        except OSError:
            pass
    finally:
        k32.CloseHandle(wt.HANDLE(h))
    return name, start


def snapshot_threads(pid):
    import psutil
    out = {}
    try:
        for t in psutil.Process(pid).threads():
            name, start = thread_info(t.id)
            out[str(t.id)] = {"name": name, "start": start, "cpu_s": round(t.user_time + t.system_time, 3)}
    except Exception as e:
        out["_error"] = str(e)
    return out


def snapshot_procs():
    import psutil
    out = {}
    for p in psutil.process_iter(["pid", "name"]):
        try:
            ct = p.cpu_times()
            out[str(p.info["pid"])] = {"name": p.info["name"], "cpu_s": round(ct.user + ct.system, 3)}
        except Exception:
            pass
    return out


def game_process():
    import psutil
    for p in psutil.process_iter(["pid", "name"]):
        if (p.info["name"] or "").lower() == GAME_EXE.lower():
            return p
    return None


# ================================================================================================= record
def record(args):
    if not is_admin():
        log("HitchWatch needs admin (kernel trace + PresentMon). Start it with 'Start HitchWatch.bat' (one UAC "
            "prompt).")
        return 2
    wpr = shutil.which("wpr") or r"C:\Windows\System32\wpr.exe"
    pm = find_presentmon()
    log(f"HitchWatch {VERSION}: wpr={'ok' if Path(wpr).is_file() else 'MISSING'}, "
        f"PresentMon={'ok' if pm else 'missing (no frame times: periodic analysis only)'}")
    proc = game_process()
    if proc is None:
        log(f"Waiting for {GAME_EXE} (up to {args.wait} min) ...")
        t_end = time.time() + args.wait * 60
        while proc is None and time.time() < t_end:
            time.sleep(2)
            proc = game_process()
        if proc is None:
            log("Game not found, nothing recorded.")
            return 1
        log(f"Game found (pid {proc.pid}). Give it time to reach gameplay; countdown starts at {args.delay} s.")
    pid = proc.pid
    folder = OUT / dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    folder.mkdir(parents=True, exist_ok=True)
    # The output folder may sit behind a directory junction; wpr rejects a -recordtempto path that goes
    # through a junction ("Invalid temporary trace directory", 0xc5586004), so hand it the real path
    folder = folder.resolve()
    try:
        import psutil
        psutil.Process().nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    except Exception:
        pass

    log(f"Go back into the game and play where the hitches happen. Recording {args.seconds} s starts in "
        f"{args.delay} s (one beep = start, two beeps = done).")
    for i in range(args.delay, 0, -1):
        print(f"  {i:2d} s ...", end="\r", flush=True)
        time.sleep(1)
    print(" " * 20, end="\r")

    frames_only = getattr(args, "frames_only", False)
    tmp = folder / "wpr-temp"
    if frames_only:
        if not pm:
            log("PresentMon missing: frames-only mode needs it. Nothing recorded.")
            return 1
    else:
        subprocess.run([wpr, "-cancel", "-instancename", INSTANCE], capture_output=True, text=True)
        tmp.mkdir(exist_ok=True)
        r = subprocess.run([wpr, "-start", f"{WPRP}!HitchWatch", "-filemode", "-recordtempto", str(tmp),
                            "-instancename", INSTANCE], capture_output=True, text=True)
        if r.returncode != 0:
            log(f"wpr -start failed ({r.returncode}): {(r.stdout + r.stderr).strip()[-400:]}")
            return 1
    a0 = anchor()
    pm_procs = []  # (session name, Popen)
    if pm:
        base = [str(pm), "--process_id", str(pid), "--qpc_time", "--v2_metrics", "--no_console_stats",
                "--stop_existing_session", "--terminate_on_proc_exit", "--timed", str(args.seconds + 1),
                "--terminate_after_timed"]
        # 2026-11-22: full PresentMon tracking lost ~10k ETW events/s (580k-613k per minute, at any priority, with or
        # without the kernel trace) and then wrote no frames.csv at all. frames.csv now skips GPU-work and input
        # tracking (the chattiest providers); frames-only mode adds a minimal present-cadence session (no display
        # tracking either) that always yields rows: frames_app.csv
        variants = [(PM_SESSION, "frames.csv", ["--no_track_gpu", "--no_track_input"])]
        if getattr(args, "frames_only", False):
            variants.append((PM_SESSION + "B", "frames_app.csv", ["--no_track_display", "--no_track_gpu", "--no_track_input"]))
        for sess, fname, extra in variants:
            cmd = base + ["--output_file", str(folder / fname), "--session_name", sess] + extra
            if fname == "frames_app.csv":
                # no process filter: 2026-11-22 03:35 even the minimal session found no presents for the game pid;
                # recording every process shows whether the game's frames arrive under another process / name
                cmd = [c for c in cmd if c not in ("--terminate_on_proc_exit",)]
                i = cmd.index("--process_id")
                del cmd[i:i + 2]
            try:
                pm_procs.append((sess, subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                                        creationflags=subprocess.NORMAL_PRIORITY_CLASS)))
            except OSError as e:
                log(f"PresentMon did not start: {e}")
    beep(1000, 180)
    log(f"RECORDING {args.seconds} s (game pid {pid}) ...")
    thr0 = snapshot_threads(pid)
    procs0 = snapshot_procs()
    t_stop = time.time() + args.seconds
    game_gone = False
    while time.time() < t_stop:
        time.sleep(min(5.0, max(0.1, t_stop - time.time())))
        if not psutil_alive(pid):
            game_gone = True
            log("Game exited during the recording.")
            break
        left = int(t_stop - time.time())
        if left > 0 and left % 15 < 5:
            print(f"  {left:3d} s left", end="\r", flush=True)
    thr1 = snapshot_threads(pid) if not game_gone else {}
    procs1 = snapshot_procs()
    a1 = anchor()
    beep(1000, 120)
    time.sleep(0.12)
    beep(1000, 120)
    if frames_only:
        log("Recording done, you can keep playing.")
        wpr_out = "frames-only (no kernel trace)"
    else:
        log("Recording done, you can keep playing. Saving the trace (takes up to a minute) ...")
        r = subprocess.run([wpr, "-stop", str(folder / "trace.etl"), "HitchWatch capture", "-skipPdbGen",
                            "-instancename", INSTANCE], capture_output=True, text=True, timeout=900)
        wpr_out = (r.stdout + r.stderr).strip()
        if r.returncode != 0:
            log(f"wpr -stop returned {r.returncode}: {wpr_out[-400:]}")
    pm_err = ""
    for sess, proc in pm_procs:
        try:
            _, err = proc.communicate(timeout=20)
            pm_err += f"[{sess}] " + (err or b"").decode("utf-8", "replace").strip()[-300:] + " "
        except subprocess.TimeoutExpired:
            proc.kill()
            subprocess.run([str(pm), "--terminate_existing_session", "--session_name", sess], capture_output=True)
            pm_err += f"[{sess}] killed after timeout "
    shutil.rmtree(tmp, ignore_errors=True)
    cap = {"version": VERSION, "pid": pid, "exe": GAME_EXE, "seconds": args.seconds, "anchor_start": a0,
           "anchor_end": a1, "qpc_freq": qpc_freq(), "threads_start": thr0, "threads_end": thr1,
           "procs_start": procs0, "procs_end": procs1, "wpr_stop": wpr_out[-2000:], "presentmon_stderr": pm_err,
           "game_exited": game_gone, "cpu_count": os.cpu_count()}
    (folder / "capture.json").write_text(json.dumps(cap, indent=1), encoding="utf-8")
    if frames_only:
        rep = frames_report(folder, pid)
        log(f"FRAMES REPORT: {rep}")
        return 0
    etl = folder / "trace.etl"
    log(f"Saved {folder} (trace {etl.stat().st_size / 2**20:.0f} MB)" if etl.is_file() else
        f"trace.etl missing in {folder}")
    retention()
    if args.no_analyze or not etl.is_file():
        return 0
    log("Analysing (1-3 min, low priority on the E-cores) ...")
    calm_self()
    rep = analyze(folder, args)
    log(f"REPORT: {rep}")
    return 0


def psutil_alive(pid):
    try:
        import psutil
        return psutil.pid_exists(pid) and (psutil.Process(pid).name() or "").lower() == GAME_EXE.lower()
    except Exception:
        return False


def retention():
    """Keep trace.etl only for the newest KEEP_TRACES captures (reports and frames stay)."""
    if not OUT.is_dir():
        return
    caps = sorted([d for d in OUT.iterdir() if d.is_dir() and (d / "trace.etl").is_file()], key=lambda d: d.name)
    for d in caps[:-KEEP_TRACES]:
        try:
            (d / "trace.etl").unlink()
        except OSError:
            pass


# ================================================================================================= trace parsing
class ModMap:
    """Address ranges -> module id, with a lookup cache."""
    __slots__ = ("b", "e", "i", "c")

    def __init__(self):
        self.b, self.e, self.i, self.c = [], [], [], {}

    def add(self, base, size, mid):
        k = bisect.bisect_left(self.b, base)
        if k < len(self.b) and self.b[k] == base:
            self.e[k], self.i[k] = base + size, mid
        else:
            self.b.insert(k, base)
            self.e.insert(k, base + size)
            self.i.insert(k, mid)
        self.c.clear()

    def find(self, a):
        r = self.c.get(a)
        if r is None:
            k = bisect.bisect_right(self.b, a) - 1
            r = self.i[k] if k >= 0 and a < self.e[k] else 0
            if len(self.c) < 3_000_000:
                self.c[a] = r
        return r


_U32 = struct.Struct("<I")
_2U32 = struct.Struct("<II")
_Q = struct.Struct("<Q")
_SAMPLE = struct.Struct("<QI")
_IMAGE = struct.Struct("<QQI")
_STKHDR = struct.Struct("<QII")
_DPC = struct.Struct("<QQ")
_FCREATE = struct.Struct("<QQI")
_FRW = struct.Struct("<QQQQII")
_FSIMPLE = struct.Struct("<QQQI")
_FEND = struct.Struct("<QQI")
_HARDF = struct.Struct("<QQQQII")


class Collector:
    """Consumes kernel events; keeps per-sample detail only for the game process."""

    def __init__(self, reader, game_pid):
        self.rd = reader
        self.game = game_pid
        self.thr_pid, self.thr_start, self.thr_name = {}, {}, {}
        self.proc_name, self.proc_exe = {}, {}
        self.kmap = ModMap()
        self.umaps = collections.defaultdict(ModMap)
        self.mods, self.mod_ix = [""], {}
        self.game_mod_base = {}
        self.cpu_samples = collections.Counter()
        self.idle = 0
        self.first_ts = None
        self.last_ts = 0
        # all non-idle samples
        self.a_ts, self.a_pid = array.array("q"), array.array("q")
        # game samples
        self.g_ts, self.g_tid, self.g_ip = array.array("q"), array.array("L"), array.array("Q")
        self.g_mod, self.g_stk = array.array("L"), array.array("L")
        self.pending = {}
        self.stk_ix, self.stk = {(): 0}, [()]
        self._fmt = {}
        # context switches / ready events of game threads
        self.cs_ts, self.cs_tid, self.cs_kind, self.cs_info = (array.array("q"), array.array("L"),
                                                               array.array("B"), array.array("H"))
        self.rd_ts, self.rd_tid, self.rd_by = array.array("q"), array.array("L"), array.array("L")
        # DPC / ISR (all CPUs)
        self.d_end, self.d_dur, self.d_mod, self.d_isr = (array.array("q"), array.array("q"), array.array("L"),
                                                          array.array("B"))
        # file I/O issued by game threads
        self.fnames, self.fcreate = {}, {}
        self.f_ts, self.f_tid, self.f_kind = array.array("q"), array.array("L"), array.array("B")
        self.f_fo, self.f_fk, self.f_size = array.array("Q"), array.array("Q"), array.array("Q")
        self.f_end, self.f_stk = array.array("q"), array.array("L")
        self.f_open = {}
        # hard faults on game threads
        self.h_ts, self.h_dur, self.h_tid, self.h_fo, self.h_bytes = (array.array("q"), array.array("q"),
                                                                      array.array("L"), array.array("Q"),
                                                                      array.array("L"))
        self.n_stack_events = 0
        self.n_sample_events = 0
        self._purge_at = 0
        r = reader
        r.on(E.G_PROCESS, (1, 3), self.on_process)
        r.on(E.G_THREAD, (1, 3, 72), self.on_thread)
        r.on(E.G_THREAD, (36,), self.on_cswitch)
        r.on(E.G_THREAD, (50,), self.on_ready)
        r.on(E.G_IMAGE, (10, 3), self.on_image)
        r.on(E.G_PERFINFO, (46,), self.on_sample)
        r.on(E.G_PERFINFO, (66, 67, 68, 69), self.on_dpc)
        r.on(E.G_STACKWALK, (32,), self.on_stack)
        r.on(E.G_FILEIO, (0, 32, 36), self.on_fname)
        r.on(E.G_FILEIO, (64,), self.on_fcreate)
        r.on(E.G_FILEIO, (67, 68), self.on_frw)
        r.on(E.G_FILEIO, (73,), self.on_fflush)
        r.on(E.G_FILEIO, (76,), self.on_fend)
        r.on(E.G_PAGEFAULT, (32,), self.on_hardfault)

    # ---------------------------------------------------------------- registry
    def mod_id(self, path):
        k = path.lower()
        m = self.mod_ix.get(k)
        if m is None:
            m = self.mod_ix[k] = len(self.mods)
            self.mods.append(path)
        return m

    def intern(self, seq):
        t = tuple(seq)
        s = self.stk_ix.get(t)
        if s is None:
            s = self.stk_ix[t] = len(self.stk)
            self.stk.append(t)
        return s

    # ---------------------------------------------------------------- handlers
    def on_process(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 16:
            return
        p = _U32.unpack_from(d, 8)[0]
        off = E.skip_sid(d, 36 if ver >= 4 else 32)
        if off < len(d):
            name = E.astr(d, off)
            if name and len(name) < 80 and name.isprintable():
                self.proc_name[p] = name

    def on_thread(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 8:
            return
        p, t = _2U32.unpack_from(d)
        if op == 72:
            name = E.wstr(d, 8) if len(d) > 8 else ""
            if name:
                self.thr_name[t] = name
            return
        self.thr_pid[t] = p
        if len(d) >= 56:
            self.thr_start[t] = _Q.unpack_from(d, 48)[0]

    def on_image(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 58:
            return
        base, size, p = _IMAGE.unpack_from(d)
        name = E.wstr(d, 56)
        mid = self.mod_id(name)
        if base >= KBASE:
            self.kmap.add(base, size, mid)
        else:
            self.umaps[p].add(base, size, mid)
            if p == self.game and mid not in self.game_mod_base:
                self.game_mod_base[mid] = base
            if p not in self.proc_exe and name.lower().endswith(".exe"):
                self.proc_exe[p] = name

    def on_sample(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 12:
            return
        ip, t = _SAMPLE.unpack_from(d)
        self.n_sample_events += 1
        self.cpu_samples[cpu] += 1
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        if t == 0:
            self.idle += 1
            return
        p = self.thr_pid.get(t, -1)
        self.a_ts.append(ts)
        self.a_pid.append(p)
        if p == self.game:
            m = self.kmap.find(ip) if ip >= KBASE else self.umaps[p].find(ip)
            i = len(self.g_ts)
            self.g_ts.append(ts)
            self.g_tid.append(t)
            self.g_ip.append(ip)
            self.g_mod.append(m)
            self.g_stk.append(0)
            self.pending[(ts, t)] = (0, i)
            if i >= self._purge_at:
                self._purge_at = i + 50_000
                self.purge(ts)

    def purge(self, now):
        freq = self.rd.header.get("perf_freq") or 10_000_000
        if len(self.pending) > 5000:
            cut = now - 3 * freq
            self.pending = {k: v for k, v in self.pending.items() if k[0] >= cut}

    def on_stack(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 24:
            return
        ets, spid, stid = _STKHDR.unpack_from(d)
        ent = self.pending.get((ets, stid))
        if ent is None:
            return
        self.n_stack_events += 1
        n = (len(d) - 16) // 8
        st = self._fmt.get(n)
        if st is None:
            st = self._fmt[n] = struct.Struct(f"<{n}Q")
        um = self.umaps.get(spid)
        km = self.kmap
        # run-length encoded module sequence, leaf first: [mod0, frames0, mod1, frames1, ...]
        rle, last = [], -1
        for a in st.unpack_from(d, 16):
            m = km.find(a) if a >= KBASE else (um.find(a) if um is not None else 0)
            if m == last:
                rle[-1] += 1
            else:
                rle.append(m)
                rle.append(1)
                last = m
        kind, idx = ent
        arr = self.g_stk if kind == 0 else self.f_stk
        prev = arr[idx]
        if prev:  # second part of the same stack (user frames after kernel frames)
            old = list(self.stk[prev])
            if old and rle and old[-2] == rle[0]:
                old[-1] += rle[1]
                rle = rle[2:]
            rle = old + rle
        arr[idx] = self.intern(rle)

    def on_cswitch(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 15:
            return
        new, old = _2U32.unpack_from(d)
        tp, g = self.thr_pid, self.game
        if tp.get(old) == g:
            self.cs_ts.append(ts)
            self.cs_tid.append(old)
            self.cs_kind.append(1)
            self.cs_info.append(d[12] | (d[14] << 8))  # wait reason | thread state << 8
        if tp.get(new) == g:
            self.cs_ts.append(ts)
            self.cs_tid.append(new)
            self.cs_kind.append(0)
            self.cs_info.append(0)

    def on_ready(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 4:
            return
        t = _U32.unpack_from(d)[0]
        if self.thr_pid.get(t) == self.game:
            self.rd_ts.append(ts)
            self.rd_tid.append(t)
            self.rd_by.append(tid & 0xFFFFFFFF)

    def on_dpc(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 16:
            return
        init, routine = _DPC.unpack_from(d)
        dur = ts - init
        if 0 <= dur < 50_000_000:
            self.d_end.append(ts)
            self.d_dur.append(dur)
            self.d_mod.append(self.kmap.find(routine))
            self.d_isr.append(1 if op == 67 else 0)

    def on_fname(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 10:
            return
        self.fnames[_Q.unpack_from(d)[0]] = E.wstr(d, 8)

    def _fop(self, ts, t, kind, fo, fk, size, irp, want_stack):
        i = len(self.f_ts)
        self.f_ts.append(ts)
        self.f_tid.append(t)
        self.f_kind.append(kind)
        self.f_fo.append(fo)
        self.f_fk.append(fk)
        self.f_size.append(size)
        self.f_end.append(0)
        self.f_stk.append(0)
        if irp:
            self.f_open[irp] = i
        if want_stack:
            self.pending[(ts, t)] = (1, i)

    def on_fcreate(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 34:
            return
        irp, fo, t = _FCREATE.unpack_from(d)
        self.fcreate[fo] = E.wstr(d, 32)
        if self.thr_pid.get(t) == self.game:
            self._fop(ts, t, 2, fo, 0, 0, irp, True)

    def on_frw(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 40:
            return
        off, irp, fo, fk, t, size = _FRW.unpack_from(d)
        if self.thr_pid.get(t) == self.game:
            self._fop(ts, t, 0 if op == 67 else 1, fo, fk, size, irp, op == 68)

    def on_fflush(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 28:
            return
        irp, fo, fk, t = _FSIMPLE.unpack_from(d)
        if self.thr_pid.get(t) == self.game:
            self._fop(ts, t, 3, fo, fk, 0, irp, True)

    def on_fend(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 8 or not self.f_open:
            return
        i = self.f_open.pop(_Q.unpack_from(d)[0], None)
        if i is not None:
            self.f_end[i] = ts

    def on_hardfault(self, ts, tid, pid, cpu, ver, op, d):
        if len(d) < 40:
            return
        init, roff, va, fo, t, nbytes = _HARDF.unpack_from(d)
        if self.thr_pid.get(t) == self.game:
            self.h_ts.append(init)
            self.h_dur.append(max(0, ts - init))
            self.h_tid.append(t)
            self.h_fo.append(fo)
            self.h_bytes.append(nbytes)

    # ---------------------------------------------------------------- after parsing
    def file_name(self, fo, fk):
        return self.fcreate.get(fo) or self.fnames.get(fk) or self.fnames.get(fo) or ""

    def proc_label(self, p):
        if p < 0:
            return "(unknown process)"
        n = self.proc_name.get(p) or os.path.basename(self.proc_exe.get(p, "")) or "?"
        return f"{n}"


# ================================================================================================= mod ownership
_DOSMAP = None


def dos_map():
    global _DOSMAP
    if _DOSMAP is None:
        _DOSMAP = []
        buf = ctypes.create_unicode_buffer(1024)
        for L in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if k32.QueryDosDeviceW(f"{L}:", buf, 1024):
                _DOSMAP.append((buf.value.lower() + "\\", f"{L}:\\"))
        _DOSMAP.sort(key=lambda x: -len(x[0]))
    return _DOSMAP


def to_dos(path):
    if not path:
        return path
    p = path
    low = p.lower()
    if low.startswith("\\systemroot\\"):
        return os.environ.get("SystemRoot", r"C:\Windows") + p[11:]
    if low.startswith("\\??\\"):
        return p[4:]
    for dev, drive in dos_map():
        if low.startswith(dev):
            return drive + p[len(dev):]
    return p


def clean_source(src):
    s = re.sub(r"-\d+(-\d+)*$", "", src)
    m = re.match(r"^(.*?)\s+\d{3,6}\s+v?\d", s)
    if m:
        s = m.group(1)
    return s.strip() or src


GENERIC_DIRS = {"bin", "bin\\x64", "r6", "r6\\scripts", "r6\\tweaks", "r6\\storages", "r6\\input", "r6\\config",
                "archive", "archive\\pc", "archive\\pc\\mod", "red4ext", "red4ext\\plugins", "bin\\x64\\plugins",
                "bin\\x64\\plugins\\cyber_engine_tweaks", "bin\\x64\\plugins\\cyber_engine_tweaks\\mods",
                "engine", "engine\\config", "engine\\config\\platform", "engine\\config\\platform\\pc", "mods",
                "r6\\cache", "r6\\logs", "red4ext\\logs"}


class Owners:
    """Game-relative path -> Vortex mod (vortex.deployment.json), with folder fallbacks for runtime files."""

    def __init__(self):
        self.file_owner, self.dir_owner = {}, {}
        try:
            d = json.loads((GAME_DIR / "vortex.deployment.json").read_text(encoding="utf-8"))
            dirs = collections.defaultdict(collections.Counter)
            for f in d.get("files", []):
                rel, src = f.get("relPath", ""), f.get("source", "")
                if not rel or not src:
                    continue
                self.file_owner[rel.lower()] = src
                parts = rel.lower().split("\\")
                for k in range(1, len(parts)):
                    dirs["\\".join(parts[:k])][src] += 1
            self.dir_owner = {k: c.most_common(1)[0][0] for k, c in dirs.items() if k not in GENERIC_DIRS}
        except (OSError, ValueError):
            pass
        self.game_prefix = str(GAME_DIR).lower() + "\\"
        self.windir = (os.environ.get("SystemRoot", r"C:\Windows")).lower() + "\\"

    def owner(self, rel):
        low = rel.lower()
        src = self.file_owner.get(low)
        if src:
            return clean_source(src)
        parts = low.split("\\")
        for k in range(len(parts) - 1, 0, -1):
            src = self.dir_owner.get("\\".join(parts[:k]))
            if src:
                return clean_source(src)
        return ""

    def classify(self, dos_path):
        """(category, label, short path) for a module or file path."""
        if not dos_path:
            return "unknown", "(no module: JIT code (CET LuaJIT traces), hook trampolines or generated code)", ""
        low = dos_path.lower()
        base = os.path.basename(low)
        if low.startswith(self.game_prefix):
            rel = dos_path[len(self.game_prefix):]
            rlow = rel.lower()
            if base == GAME_EXE.lower():
                return "game exe", "Cyberpunk 2077 (engine + all redscript)", rel
            own = self.owner(rel)
            parts = rel.split("\\")
            if rlow.startswith("red4ext\\plugins\\") and len(parts) > 3:
                return "mod", own or parts[2], rel
            if rlow.startswith("red4ext\\"):
                return "mod", own or "RED4ext", rel
            if "cyber_engine_tweaks" in rlow:
                if rlow.startswith("bin\\x64\\plugins\\cyber_engine_tweaks\\mods\\") and len(parts) > 5:
                    return "mod", f"CET mod {parts[5]}" + (f" ({own})" if own else ""), rel
                return "mod", own or "Cyber Engine Tweaks", rel
            if rlow.startswith("r6\\storages\\") and len(parts) > 3:
                return "mod", own or f"storage of {parts[2]}", rel
            if own:
                return "mod", own, rel
            if rlow.startswith("bin\\x64\\plugins\\") or base.endswith((".asi", ".addon64", ".addon")):
                return "mod", base, rel
            if rlow.startswith("bin\\x64\\") and base in ("dxgi.dll", "d3d12.dll", "winmm.dll", "version.dll",
                                                          "dinput8.dll", "nvngx.dll", "reshade64.dll",
                                                          "dxgi.dll.dll", "d3d11.dll"):
                return "mod", f"{base} (proxy DLL: ReShade / RenoDX / OptiScaler / loader)", rel
            if rlow.startswith("archive\\pc\\content") or rlow.startswith("archive\\pc\\ep1"):
                return "game", "base game archives", rel
            return "game", "game file", rel
        if base in OVERLAY_DLLS:
            return "overlay", OVERLAY_DLLS[base], dos_path
        if "\\driverstore\\" in low or base.startswith(("nv", "nvlddmkm")) and (low.startswith(self.windir) or
                                                                                "nvidia" in low):
            return "driver", base, dos_path
        if low.startswith(self.windir):
            if "\\drivers\\" in low:
                return "driver", base, dos_path
            return "windows", base, dos_path
        if "\\saved games\\cd projekt red" in low:
            return "saves", "Cyberpunk saves / settings", dos_path
        return "other", base, dos_path


# ================================================================================================= frames
def load_frames(path, pid):
    """PresentMon CSV -> sorted list of (qpc, displayed_ms or None, cpu_busy, gpu_ms)."""
    if not path.is_file():
        return [], "frames.csv missing"
    rows = []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
        rd = csv.reader(f)
        try:
            hdr = next(rd)
        except StopIteration:
            return [], "frames.csv empty"
        keys = [re.sub(r"^ms", "", h.strip().lower()) for h in hdr]
        ix = {k: i for i, k in enumerate(keys)}
        qcol = next((ix[k] for k in ("cpustartqpc", "qpctime", "cpustartqpctime") if k in ix), None)
        if qcol is None:
            qcol = next((i for k, i in ix.items() if "qpc" in k), None)
        if qcol is None:
            return [], f"no QPC column in frames.csv ({','.join(hdr[:12])})"
        pcol = ix.get("processid")
        scol = ix.get("swapchainaddress")
        dcol = ix.get("displayedtime", ix.get("betweendisplaychange"))
        bcol = ix.get("cpubusy")
        gcol = ix.get("gputime", ix.get("gpubusy"))

        def fnum(r, c):
            if c is None or c >= len(r):
                return None
            try:
                v = float(r[c])
                return v if v == v else None
            except ValueError:
                return None
        for r in rd:
            if len(r) <= qcol:
                continue
            if pcol is not None and pcol < len(r) and r[pcol].strip() and r[pcol].strip() != str(pid):
                continue
            try:
                q = int(float(r[qcol]))
            except ValueError:
                continue
            rows.append((q, r[scol] if scol is not None and scol < len(r) else "", fnum(r, dcol), fnum(r, bcol),
                         fnum(r, gcol)))
    if not rows:
        return [], "no frames for the game in frames.csv"
    sc = collections.Counter(r[1] for r in rows).most_common(1)[0][0]
    rows = sorted((r[0], r[2], r[3], r[4]) for r in rows if r[1] == sc)
    return rows, f"{len(rows)} presents"


def rolling_median(vals, w):
    out, win, h = [], [], w // 2
    n = len(vals)
    lo = hi = 0
    for i in range(n):
        a, b = max(0, i - h), min(n, i + h + 1)
        while hi < b:
            bisect.insort(win, vals[hi])
            hi += 1
        while lo < a:
            win.pop(bisect.bisect_left(win, vals[lo]))
            lo += 1
        out.append(win[len(win) // 2])
    return out


def find_hitches(frames, freq, ratio, extra, min_gap):
    # frame generation presents its frames in bursts ~0.5 ms apart: one burst = one real (app) frame
    q = []
    for f in frames:
        if not q or (f[0] - q[-1]) * 1000.0 / freq >= 3.0:
            q.append(f[0])
    iv = [(q[i + 1] - q[i]) * 1000.0 / freq for i in range(len(q) - 1)]
    if len(iv) < 20:
        return [], 0.0, []
    med = rolling_median(iv, 121)
    raw = []
    for i, v in enumerate(iv):
        m = med[i]
        if v >= max(m * ratio, m + extra, min_gap):
            raw.append([q[i], q[i + 1], v, m, i + 1])
    merged = []
    for h in raw:
        if merged and (h[0] - merged[-1][1]) * 1000.0 / freq < 100:
            m = merged[-1]
            m[1] = h[1]
            m[2] = max(m[2], h[2])
        else:
            merged.append(list(h))
    # display-only hitches: a frame stays on screen far longer than usual while presents kept coming
    disp = [(frames[i][0], frames[i][1]) for i in range(len(frames)) if frames[i][1] is not None]
    disp_only = []
    if len(disp) > 50:
        dmed = rolling_median([d[1] for d in disp], 121)
        hz = [(h[0] - int(0.05 * freq), h[1] + int(0.1 * freq)) for h in merged]
        for (t, v), m in zip(disp, dmed):
            if v >= max(m * ratio, m + extra, min_gap) and not any(a <= t <= b for a, b in hz):
                if not disp_only or (t - disp_only[-1][0]) > 0.1 * freq:
                    disp_only.append((t, v, m))
    return merged, statistics.median(iv), disp_only


# ================================================================================================= analysis
class Analysis:
    def __init__(self, col, cap, owners, freq):
        self.c = col
        self.cap = cap
        self.own = owners
        self.freq = freq
        self.tick_ms = 1000.0 / freq
        dur_ticks = max(1, col.last_ts - (col.first_ts or col.last_ts))
        per_cpu = max(col.cpu_samples.values()) if col.cpu_samples else 0
        est = dur_ticks * self.tick_ms / per_cpu if per_cpu else 1.0
        self.sample_ms = est if 0.1 <= est <= 20 else 1.0
        self.t0, self.t1 = col.first_ts or 0, col.last_ts
        # module classification
        self.mod_cls = {}
        for mid, path in enumerate(col.mods):
            self.mod_cls[mid] = owners.classify(to_dos(path)) if mid else owners.classify("")
        self.exe_mid = next((m for m, p in enumerate(col.mods) if p.lower().endswith("\\" + GAME_EXE.lower())), -1)
        # thread names: live snapshot first, ETW names second
        self.tname = {}
        for snap in (cap.get("threads_end") or {}, cap.get("threads_start") or {}):
            for k, v in snap.items():
                if k.isdigit() and v.get("name") and int(k) not in self.tname:
                    self.tname[int(k)] = v["name"]
        for t, n in col.thr_name.items():
            self.tname.setdefault(t, n)
        self.tstart = dict(col.thr_start)
        for snap in (cap.get("threads_start") or {}, cap.get("threads_end") or {}):
            for k, v in snap.items():
                if k.isdigit() and v.get("start"):
                    self.tstart.setdefault(int(k), v["start"])
        self.gt = next((t for t, n in self.tname.items() if n == "GameThread" and col.thr_pid.get(t) == col.game),
                       None)
        if self.gt is None:
            cnt = collections.Counter(col.g_tid)
            self.gt = cnt.most_common(1)[0][0] if cnt else 0
            self.gt_named = False
        else:
            self.gt_named = True
        self.incl_cache = {}
        self.leafmod_cache = {}
        self.build_thread_index()
        self.build_wrappers()
        self.build_gt_segments()

    # ---------------------------------------------------------------- labels
    def mlabel(self, mid):
        cat, label, short = self.mod_cls.get(mid, ("unknown", "?", ""))
        base = os.path.basename(short) if short else ""
        if cat in ("mod", "overlay") and base and base.lower() not in label.lower():
            return f"{label} [{base}]"
        if cat in ("game", "other", "windows", "driver") and base:
            return base if label in (base, "game file") else f"{label} [{base}]"
        return label

    def tlabel(self, t):
        if t == self.gt:
            return "GameThread"
        n = self.tname.get(t)
        if n:
            return n
        st = self.tstart.get(t)
        sm = self.c.umaps[self.c.game].find(st) if st else 0
        return f"tid {t}" + (f" [{os.path.basename(self.c.mods[sm])}]" if sm else "")

    def thread_owner_label(self, t):
        """Label of any thread (game or not) for 'woken by'."""
        p = self.c.thr_pid.get(t, -1)
        if t in (0, 0xFFFFFFFF) or p in (0, -1):
            return "interrupt / DPC / idle (timer or I/O completion)"
        if p == self.c.game:
            return self.tlabel(t)
        return f"{self.c.proc_label(p)} (other process)" if p != 4 else "System (kernel worker)"

    def incl(self, sid, ipmod):
        key = (sid, ipmod)
        r = self.incl_cache.get(key)
        if r is None:
            s = set(self.c.stk[sid][0::2]) if sid else set()
            s.add(ipmod)
            r = self.incl_cache[key] = frozenset(s)
        return r

    def tgroup(self, t):
        n = self.tname.get(t)
        if n:
            return re.sub(r"[\s_#-]*\d+$", "", n) or n
        st = self.tstart.get(t)
        sm = self.c.umaps[self.c.game].find(st) if st else 0
        return "start:" + os.path.basename(self.c.mods[sm]) if sm else "unnamed"

    def build_wrappers(self):
        """Mod frames that wrap a thread's whole work (CET's main-loop tick hook, a plugin's thread loop): the same
        module at the same depth from the thread root in >= 50% of the thread's samples. They are skipped when
        work is charged to the nearest mod on the stack, otherwise CET would own every GameThread sample."""
        c = self.c
        pairs = collections.Counter(zip(c.g_tid, c.g_stk))
        thr_tot, grp_tot = collections.Counter(), collections.Counter()
        per_thr, per_grp = collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
        for (t, sid), n in pairs.items():
            g = self.tgroup(t)
            thr_tot[t] += n
            grp_tot[g] += n
            if not sid:
                continue
            st = c.stk[sid]
            depth = 0
            for k in range(len(st) - 2, -1, -2):  # root side first
                m, rl = st[k], st[k + 1]
                if self.mod_cls[m][0] in OWNER_CATS:
                    per_thr[t][(m, depth)] += n
                    per_grp[g][(m, depth)] += n
                depth += rl
        self.wrap = {}
        for t, tot in thr_tot.items():
            if tot >= 300:
                src, total = per_thr[t], tot
            else:
                g = self.tgroup(t)
                src, total = per_grp[g], grp_tot[g]
            self.wrap[t] = frozenset(k for k, v in src.items() if v >= 0.5 * total)
        self.gt_wrapper_mods = {m for m, _ in self.wrap.get(self.gt, ())}

    def leaf_mod(self, t, sid, ipmod):
        """Who asked for this work: the CPU's own module when it is a mod, else the first mod frame from the
        leaf that is not a whole-thread wrapper, else the module the CPU was in."""
        key = (t, sid, ipmod)
        r = self.leafmod_cache.get(key)
        if r is None:
            r = ipmod
            if self.mod_cls.get(ipmod, ("",))[0] not in OWNER_CATS and sid:
                st = self.c.stk[sid]
                wr = self.wrap.get(t, ())
                total = sum(st[1::2])
                pos = 0
                for k in range(0, len(st), 2):
                    m, rl = st[k], st[k + 1]
                    pos += rl
                    if self.mod_cls.get(m, ("",))[0] in OWNER_CATS and (m, total - pos) not in wr:
                        r = m
                        break
            self.leafmod_cache[key] = r
        return r

    # ---------------------------------------------------------------- indexes
    def build_thread_index(self):
        self.t_samples = collections.defaultdict(lambda: (array.array("q"), array.array("L")))
        c = self.c
        for i in range(len(c.g_ts)):
            ts_a, ix_a = self.t_samples[c.g_tid[i]]
            ts_a.append(c.g_ts[i])
            ix_a.append(i)

    def build_gt_segments(self):
        """GameThread timeline: (start, end, kind, reason, woken_by); kind 0 run, 1 wait, 2 ready."""
        c, gt = self.c, self.gt
        ev = []
        for i in range(len(c.cs_ts)):
            if c.cs_tid[i] == gt:
                ev.append((c.cs_ts[i], 1 if c.cs_kind[i] == 1 else 2, c.cs_info[i]))
        for i in range(len(c.rd_ts)):
            if c.rd_tid[i] == gt:
                ev.append((c.rd_ts[i], 0, c.rd_by[i]))
        ev.sort()
        segs = []
        state, since, reason, by = None, None, 0, 0
        for ts, typ, info in ev:
            if typ == 2:  # switch in
                if state is not None and since is not None:
                    segs.append((since, ts, state, reason, by))
                state, since, reason, by = 0, ts, 0, 0
            elif typ == 1:  # switch out
                if state == 0 and since is not None:
                    segs.append((since, ts, 0, 0, 0))
                st = info >> 8
                if st == 5:
                    state, since, reason, by = 1, ts, info & 0xFF, 0
                else:
                    state, since, reason, by = 2, ts, 255, 0  # preempted, ready to run
            else:  # readied
                if state == 1 and since is not None:
                    segs.append((since, ts, 1, reason, info))
                    state, since, reason, by = 2, ts, 254, info
        self.gt_segs = segs
        self.gt_seg_start = [s[0] for s in segs]

    # ---------------------------------------------------------------- window metrics
    def window(self, a, b):
        """Metrics for [a, b) in raw ticks. Values in ms unless the family name says otherwise."""
        c, sms = self.c, self.sample_ms
        M = collections.defaultdict(collections.Counter)
        # game samples
        i0, i1 = bisect.bisect_left(c.g_ts, a), bisect.bisect_left(c.g_ts, b)
        gt = self.gt
        exe = self.exe_mid
        for i in range(i0, i1):
            t, m, sid = c.g_tid[i], c.g_mod[i], c.g_stk[i]
            inc = self.incl(sid, m)
            M["thr"][t] += sms
            M["mx"][m] += sms
            for x in inc:
                M["mi"][x] += sms
            lm = self.leaf_mod(t, sid, m)
            M["leaf"][lm] += sms
            if t == gt:
                M["mx_gt"][m] += sms
                M["leaf_gt"][lm] += sms
                for x in inc:
                    M["mi_gt"][x] += sms
                if m == exe:
                    base = c.game_mod_base.get(exe, 0)
                    M["rva_gt"][(c.g_ip[i] - base) & ~0xFF] += sms
            M["game"]["cpu"] += sms
        # other processes
        j0, j1 = bisect.bisect_left(c.a_ts, a), bisect.bisect_left(c.a_ts, b)
        for j in range(j0, j1):
            p = c.a_pid[j]
            if p != c.game:
                M["proc"][p] += sms
        # GameThread states
        k = max(0, bisect.bisect_right(self.gt_seg_start, a) - 1)
        segs = self.gt_segs
        while k < len(segs) and segs[k][0] < b:
            s, e, kind, reason, by = segs[k]
            ov = (min(e, b) - max(s, a)) * self.tick_ms
            if ov > 0:
                M["gt"][("run", "wait", "ready")[kind]] += ov
                if kind == 1:
                    rn = WAIT_REASONS[reason] if reason < len(WAIT_REASONS) else str(reason)
                    M["gt_wait"][rn] += ov
                    wl = self.thread_owner_label(by) if by else "(not woken yet / unknown)"
                    M["gt_wait_by"][wl] += ov
                    if by and c.thr_pid.get(by) == c.game and by in self.t_samples:
                        ts_a, ix_a = self.t_samples[by]
                        x0, x1 = bisect.bisect_left(ts_a, max(s, a)), bisect.bisect_left(ts_a, min(e, b))
                        for x in range(x0, x1):
                            ii = ix_a[x]
                            M["waited_leaf"][self.leaf_mod(by, c.g_stk[ii], c.g_mod[ii])] += sms
                            M["waited_thr"][by] += sms
            k += 1
        # DPC / ISR
        d0, d1 = bisect.bisect_left(c.d_end, a), bisect.bisect_left(c.d_end, b)
        for d in range(d0, d1):
            ms = c.d_dur[d] * self.tick_ms
            m = c.d_mod[d]
            M["dpc"][m] += ms
            if ms > M["dpc_max"][m]:
                M["dpc_max"][m] = ms
        # file I/O issued by game threads
        f0, f1 = bisect.bisect_left(c.f_ts, a), bisect.bisect_left(c.f_ts, b)
        for f in range(f0, f1):
            kind = c.f_kind[f]
            key = (c.f_fo[f], c.f_fk[f])
            if kind != 0:
                M["fw"][key] += 1
            else:
                M["fr"][key] += 1
                M["fr_bytes"][key] += c.f_size[f]
            if c.f_tid[f] == gt and c.f_end[f]:
                M["fio_gt"][key] += (c.f_end[f] - c.f_ts[f]) * self.tick_ms
        # hard faults
        h0, h1 = bisect.bisect_left(c.h_ts, a), bisect.bisect_left(c.h_ts, b)
        for h in range(h0, h1):
            M["hf"]["count"] += 1
            if c.h_tid[h] == gt:
                M["hf_gt"]["count"] += 1
                M["hf_gt"]["ms"] += c.h_dur[h] * self.tick_ms
        return M


def excess_table(fam, hw, hd, nw, nd, base, thr, top=25, keyfilter=None):
    """Per key: mean value in hitch windows, expected (base rate x duration), mean excess, coverage, false rate.
    hw / nw: lists of Counters for hitch / normal windows; hd / nd: their durations in ms; base: Counter over the
    whole trace (rate = base / total_ms)."""
    total_ms, base_c = base
    keys = set()
    for w in hw:
        keys.update(w.keys())
    out = []
    for k in keys:
        if keyfilter and not keyfilter(k):
            continue
        rate = base_c.get(k, 0) / total_ms if total_ms else 0
        exc = [w.get(k, 0) - rate * d for w, d in zip(hw, hd)]
        vals = [w.get(k, 0) for w in hw]
        cov = sum(1 for e in exc if e >= thr) / len(hw)
        fr = (sum(1 for w, d in zip(nw, nd) if w.get(k, 0) - rate * d >= thr) / len(nw)) if nw else 0
        out.append({"key": k, "hitch_mean": statistics.mean(vals), "expected": rate * statistics.mean(hd),
                    "excess": statistics.mean(exc), "coverage": cov, "false_rate": fr,
                    "score": max(0.0, statistics.mean(exc)) * cov * (1 - fr)})
    out.sort(key=lambda r: (0 if r["score"] > 0 else 1, -r["score"], -r["excess"]))
    return out[:top]


# ================================================================================================= periodicity
def bursts_of(series, nbins, min_abs, merge_bins=4):
    """series: Counter(bin -> value). Returns burst start bins (value > mean + 4 sd and >= min_abs)."""
    if not series or nbins < 10:
        return []
    tot = sum(series.values())
    mean = tot / nbins
    var = sum((v - mean) ** 2 for v in series.values()) + (nbins - len(series)) * mean * mean
    sd = (var / nbins) ** 0.5
    thr = max(min_abs, mean + 4 * sd)
    hits = sorted(b for b, v in series.items() if v >= thr)
    out = []
    for b in hits:
        if out and b - out[-1][1] <= merge_bins:
            out[-1][1] = b
        else:
            out.append([b, b])
    return [o[0] for o in out]


def periodicity(times_s):
    if len(times_s) < 4:
        return None
    iv = [b - a for a, b in zip(times_s, times_s[1:])]
    p = statistics.median(iv)
    mad = statistics.median([abs(x - p) for x in iv])
    return p, mad, len(times_s)


# ================================================================================================= report
def fmt_ms(v):
    return f"{v:.1f}" if abs(v) < 100 else f"{v:.0f}"


def analyze(folder, args=None):
    folder = Path(folder)
    min_gap = getattr(args, "min_gap_ms", 25.0) if args else 25.0
    ratio = getattr(args, "ratio", 2.5) if args else 2.5
    extra = getattr(args, "extra_ms", 18.0) if args else 18.0
    lead = getattr(args, "lead_ms", 60.0) if args else 60.0
    cap = {}
    if (folder / "capture.json").is_file():
        cap = json.loads((folder / "capture.json").read_text(encoding="utf-8"))
    pid = cap.get("pid") or getattr(args, "pid", None)
    etl = folder / "trace.etl"
    if not etl.is_file():
        raise SystemExit(f"no trace.etl in {folder}")
    if not pid:
        pid = find_pid_in_trace(etl)
    t_start = time.time()
    rd = E.EtlReader(etl)
    col = Collector(rd, int(pid))
    rd.progress = lambda n: print(f"  {n / 1e6:.0f}M events ...", end="\r", flush=True)
    hdr = rd.run()
    print(" " * 30, end="\r")
    parse_s = time.time() - t_start
    log(f"Parsed {rd.total:,} events ({rd.handled:,} used) in {parse_s:.0f} s; game samples {len(col.g_ts):,}, "
        f"stacks {col.n_stack_events:,}, errors {rd.errors}")
    freq = hdr["perf_freq"] or 10_000_000
    owners = Owners()
    A = Analysis(col, cap, owners, freq)
    notes = []
    if hdr.get("events_lost") or hdr.get("buffers_lost") or hdr.get("events_lost_read"):
        notes.append(f"ETW lost events: {hdr.get('events_lost')} events / {hdr.get('buffers_lost')} buffers "
                     "(the trace has gaps; numbers may be a little low).")
    if rd.errors:
        notes.append(f"{rd.errors} events failed to decode (first: {rd.first_errors[0].splitlines()[-1]}).")
    if hdr["clock"] != "QPC":
        notes.append(f"Trace clock is {hdr['clock']}, not QPC: frame alignment uses the capture anchors.")

    # ------------------------------------------------------------ frames and hitches
    frames, fnote = load_frames(folder / "frames.csv", pid)
    if frames and hdr["clock"] != "QPC" and cap.get("anchor_start"):
        an = cap["anchor_start"]
        qf = cap.get("qpc_freq") or freq
        frames = [(int(an["filetime"] + (q - an["qpc"]) * 1e7 / qf),) + f[1:] for f in frames for q in [f[0]]]
    hitches, med_frame, disp_only = ([], 0.0, [])
    if frames:
        hitches, med_frame, disp_only = find_hitches(frames, freq, ratio, extra, min_gap)
        overlap = [h for h in hitches if A.t0 <= h[0] <= A.t1]
        if hitches and not overlap:
            notes.append("PresentMon frames do not overlap the trace in time: hitch windows skipped.")
        hitches = overlap
    else:
        notes.append(f"No PresentMon frames ({fnote}): no hitch windows, only totals and periodic sources.")

    def wall(ts):
        an = cap.get("anchor_start")
        if hdr["clock"] == "QPC" and an:
            u = an["unix"] + (ts - an["qpc"]) / freq
        elif hdr["clock"] == "SystemTime":
            u = ts / 1e7 - 11644473600.0
        else:
            u = (hdr["start_filetime"] / 1e7 - 11644473600.0) + (ts - A.t0) / freq
        d = dt.datetime.fromtimestamp(u)
        return f"{d:%H:%M:%S}.{d.microsecond // 1000:03d}"

    lead_t = int(lead / 1000 * freq)
    hwin = [(max(A.t0, h[0] - lead_t), h[1]) for h in hitches]
    hd = [(b - a) * A.tick_ms for a, b in hwin]
    log(f"{len(hitches)} hitches; computing windows ...")
    HW = [A.window(a, b) for a, b in hwin]
    # normal windows: random, away from hitches
    rnd = random.Random(7)
    nlen = int(statistics.median(hd) / A.tick_ms) if hd else int(0.1 * freq)
    guard = int(0.3 * freq)
    nwin = []
    tries = 0
    while len(nwin) < 120 and tries < 5000 and A.t1 - A.t0 > nlen * 3:
        tries += 1
        s = rnd.randint(A.t0, A.t1 - nlen)
        if any(s < h[1] + guard and s + nlen > h[0] - lead_t - guard for h in hitches):
            continue
        nwin.append((s, s + nlen))
    NW = [A.window(a, b) for a, b in nwin]
    nd = [(b - a) * A.tick_ms for a, b in nwin]
    G = A.window(A.t0, A.t1 + 1)
    total_ms = (A.t1 - A.t0) * A.tick_ms or 1.0

    def fam(name):
        return [w[name] for w in HW], [w[name] for w in NW], (total_ms, G[name])

    def xt(name, thr, top=25, keyfilter=None):
        if not HW:
            return []
        h, n, base = fam(name)
        return excess_table(name, h, hd, n, nd, base, thr, top, keyfilter)

    gtx = xt("gt", 3.0)
    t_mi_gt = xt("mi_gt", 3.0, 40, lambda m: A.mod_cls[m][0] not in ("game exe",))
    t_leaf_gt = xt("leaf_gt", 3.0, 25)
    t_leaf = xt("leaf", 3.0, 25)
    t_mx = xt("mx", 3.0, 25)
    t_thr = xt("thr", 3.0, 20)
    t_wait = xt("gt_wait", 3.0, 12)
    t_wby = xt("gt_wait_by", 3.0, 12)
    t_wleaf = xt("waited_leaf", 3.0, 15)
    t_wthr = xt("waited_thr", 3.0, 12)
    t_proc = xt("proc", 3.0, 15, lambda p: p > 0)
    t_dpc = xt("dpc", 0.5, 12)
    t_fw = xt("fw", 1.0, 15)
    t_fio = xt("fio_gt", 1.0, 10)
    t_hf = xt("hf_gt", 1.0, 2)
    t_rva = xt("rva_gt", 2.0, 12)

    # ------------------------------------------------------------ periodic sources
    BIN = int(0.025 * freq)
    nbins = max(1, (A.t1 - A.t0) // BIN + 1)
    series = collections.defaultdict(collections.Counter)
    c = col
    sms = A.sample_ms
    for i in range(len(c.g_ts)):
        b = (c.g_ts[i] - A.t0) // BIN
        t, m, sid = c.g_tid[i], c.g_mod[i], c.g_stk[i]
        if t == A.gt:
            series[("GameThread CPU", "")][b] += sms
        series[("game thread", t)][b] += sms
        lm = A.leaf_mod(t, sid, m)
        if A.mod_cls[lm][0] in SUSPECT_CATS:
            series[("module", lm)][b] += sms
    for j in range(len(c.a_ts)):
        p = c.a_pid[j]
        if p != c.game and p > 0:
            series[("process", p)][(c.a_ts[j] - A.t0) // BIN] += sms
    for d in range(len(c.d_end)):
        series[("driver DPC/ISR", c.d_mod[d])][(c.d_end[d] - A.t0) // BIN] += c.d_dur[d] * A.tick_ms
    fname_cache = {}

    def fid(fo, fk):
        k = (fo, fk)
        r = fname_cache.get(k)
        if r is None:
            r = fname_cache[k] = to_dos(col.file_name(fo, fk)) or "(unnamed file)"
        return r
    for f in range(len(c.f_ts)):
        if c.f_kind[f] != 0:
            series[("file write", fid(c.f_fo[f], c.f_fk[f]))][(c.f_ts[f] - A.t0) // BIN] += 1
    for h in range(len(c.h_ts)):
        series[("hard faults", "game")][(c.h_ts[h] - A.t0) // BIN] += 1
    hz = [(a - int(0.15 * freq), b + int(0.15 * freq)) for a, b in hwin]
    periodic = []
    for key, s in series.items():
        kind = key[0]
        total = sum(s.values())
        if kind in ("module", "game thread", "process") and total < 30 * sms:
            continue
        min_abs = {"driver DPC/ISR": 0.3, "file write": 1, "hard faults": 1}.get(kind, 3 * sms)
        bs = bursts_of(s, nbins, min_abs)
        if len(bs) < 4 or len(bs) > nbins * 0.3:
            continue
        times = [A.t0 + b * BIN for b in bs]
        per = periodicity([t / freq for t in times])
        if not per:
            continue
        p, mad, n = per
        at_h = sum(1 for t in times if any(a <= t <= b for a, b in hz))
        regular = 1.0 <= p <= 20 and mad <= 0.25 * p
        if not regular and not (hz and at_h >= 3 and at_h / n >= 0.6):
            continue
        periodic.append({"kind": kind, "key": key[1], "bursts": n, "period": p, "mad": mad, "at_hitch": at_h,
                         "regular": regular, "total": total})

    # ------------------------------------------------------------ hitch period
    h_times = [h[0] / freq for h in hitches]
    hper = periodicity(h_times) if len(h_times) >= 4 else None

    def name_of(kind, key):
        if kind == "module" or kind == "driver DPC/ISR":
            return A.mlabel(key)
        if kind == "game thread":
            return A.tlabel(key)
        if kind == "process":
            return col.proc_label(key)
        if kind == "file write":
            return file_label(owners, key)
        return str(key) if key else kind

    for p in periodic:
        p["name"] = name_of(p["kind"], p["key"])
        p["match"] = (abs(p["period"] - hper[0]) <= max(0.35, 0.15 * hper[0])) if hper else False
    periodic.sort(key=lambda p: (-(p["at_hitch"] / p["bursts"]) if hitches else 0, not p["match"],
                                 not p["regular"], p["mad"] / max(p["period"], 0.01)))

    # ------------------------------------------------------------ suspects
    suspects = []

    def add_s(kind, label, row, unit="ms", detail=""):
        suspects.append({"kind": kind, "label": label, "excess": row["excess"], "coverage": row["coverage"],
                         "false_rate": row["false_rate"], "score": row["score"], "unit": unit,
                         "expected": row["expected"], "detail": detail})
    for kind, rows in (("code on GameThread", t_leaf_gt), ("work GameThread waited for", t_wleaf),
                       ("code in the game, all threads", t_leaf), ("CPU inside the module, all threads", t_mx)):
        for r in rows:
            if A.mod_cls[r["key"]][0] in SUSPECT_CATS and r["score"] > 0:
                add_s(kind, A.mlabel(r["key"]), r, detail=A.mod_cls[r["key"]][2])
    for r in t_proc:
        if r["score"] > 0:
            add_s("other process CPU", col.proc_label(r["key"]), r)
    for r in t_dpc:
        if r["score"] > 0:
            add_s("driver DPC/ISR", A.mlabel(r["key"]), r)
    for r in t_fw:
        if r["score"] > 0:
            add_s("file writes by the game", file_label(owners, fid(*r["key"])), r, unit="ops")
    for r in t_fio:
        if r["score"] > 0:
            add_s("GameThread file I/O time", file_label(owners, fid(*r["key"])), r)
    for r in t_hf:
        if r["key"] == "ms" and r["score"] > 0:
            add_s("GameThread hard page faults", "paging (RAM pressure / memory-mapped files)", r)
    best = {}
    for s in suspects:
        k = s["label"]
        if k not in best or s["score"] > best[k]["score"]:
            best[k] = s
    suspects = sorted(best.values(), key=lambda s: -s["score"])

    # ------------------------------------------------------------ hitch classification
    per_hitch = []
    gt_rate = {k: G["gt"].get(k, 0) / total_ms for k in ("run", "wait", "ready")}
    for (h, (a, b), w, d) in zip(hitches, hwin, HW, hd):
        gap_x = h[2] - h[3]
        ex = {k: w["gt"].get(k, 0) - gt_rate[k] * d for k in ("run", "wait", "ready")}
        mods = collections.Counter({m: v - G["leaf_gt"].get(m, 0) / total_ms * d for m, v in w["leaf_gt"].items()
                                    if A.mod_cls[m][0] in SUSPECT_CATS})
        topm = mods.most_common(1)
        exe_x = w["leaf_gt"].get(A.exe_mid, 0) - G["leaf_gt"].get(A.exe_mid, 0) / total_ms * d
        cand = {"code": topm[0][1] if topm else 0.0, "exe": exe_x, "wait": ex["wait"], "ready": ex["ready"]}
        top_k = max(cand, key=lambda k: cand[k])
        if cand[top_k] < 0.3 * gap_x:
            verdict = "not GameThread (render / GPU / present side)"
        elif top_k == "code":
            verdict = f"GameThread busy: {A.mlabel(topm[0][0])}"
        elif top_k == "exe":
            verdict = "GameThread busy: engine / redscript (exe only)"
        elif top_k == "wait":
            verdict = "GameThread waiting" + (f" ({w['gt_wait'].most_common(1)[0][0]})" if w["gt_wait"] else "")
        else:
            verdict = "GameThread starved of CPU (ready, not running)"
        wl = w["waited_leaf"].most_common(1)
        procs = collections.Counter({p: v - G["proc"].get(p, 0) / total_ms * d for p, v in w["proc"].items()})
        topp = procs.most_common(1)
        dmax = max(w["dpc_max"].items(), key=lambda kv: kv[1]) if w["dpc_max"] else None
        nfw = sum(w["fw"].values())
        per_hitch.append({
            "time": wall(h[0]), "gap": h[2], "median": h[3], "verdict": verdict,
            "gt_run": w["gt"].get("run", 0), "gt_wait": w["gt"].get("wait", 0), "gt_ready": w["gt"].get("ready", 0),
            "win": d,
            "top_gt_code": f"{A.mlabel(topm[0][0])} +{topm[0][1]:.0f}" if topm and topm[0][1] >= 2 else "",
            "waited_on": f"{A.mlabel(wl[0][0])} {wl[0][1]:.0f}" if wl and wl[0][1] >= 2 else "",
            "woken_by": w["gt_wait_by"].most_common(1)[0][0] if w["gt_wait_by"] else "",
            "other_proc": f"{col.proc_label(topp[0][0])} +{topp[0][1]:.0f}" if topp and topp[0][1] >= 3 else "",
            "dpc_max": f"{A.mlabel(dmax[0])} {dmax[1]:.2f}" if dmax and dmax[1] >= 0.25 else "",
            "file_writes": nfw, "hard_faults_gt": w["hf_gt"].get("count", 0),
        })
    verdicts = collections.Counter(re.sub(r" \((?!engine|ready|render)[^)]*\)$", "", p["verdict"]) for p in per_hitch)

    # ------------------------------------------------------------ module totals ("measure all the mods")
    mod_rows = []
    gt_samples = collections.Counter()
    for i in range(len(c.g_ts)):
        if c.g_tid[i] == A.gt:
            gt_samples[c.g_mod[i]] += 1
    dur_s = total_ms / 1000.0
    for mid in set(list(G["mi"].keys()) + list(G["mx"].keys())):
        cat, label, short = A.mod_cls[mid]
        mod_rows.append({"module": A.mlabel(mid), "category": cat, "path": short or col.mods[mid],
                         "excl_ms": G["mx"].get(mid, 0), "incl_ms": G["mi"].get(mid, 0),
                         "gt_incl_ms": G["mi_gt"].get(mid, 0), "leaf_ms": G["leaf"].get(mid, 0),
                         "leaf_gt_ms": G["leaf_gt"].get(mid, 0)})
    for r in mod_rows:
        r["leaf_ms_per_s"] = r["leaf_ms"] / dur_s
    mod_rows.sort(key=lambda r: -r["leaf_ms"])
    loaded_mods = [(mid, A.mod_cls[mid]) for mid in sorted(set(col.umaps[col.game].i))
                   if A.mod_cls[mid][0] in ("mod", "overlay")]

    # ------------------------------------------------------------ write
    rep = build_report(folder, cap, hdr, A, col, owners, hitches, med_frame, disp_only, per_hitch, verdicts, hper,
                       suspects, periodic, gtx, t_mi_gt, t_leaf_gt, t_leaf, t_mx, t_thr, t_wait, t_wby, t_wleaf,
                       t_wthr, t_proc, t_dpc, t_fw, t_fio, t_hf, t_rva, mod_rows, loaded_mods, G, total_ms, notes,
                       fid, frames, fnote, parse_s, rd, min_gap, ratio, extra, lead, len(nwin))
    write_csvs(folder, per_hitch, mod_rows, periodic)
    summary = {"version": VERSION, "folder": folder.name, "duration_s": dur_s, "hitches": len(hitches),
               "hitches_per_min": len(hitches) / dur_s * 60 if dur_s else 0, "median_frame_ms": med_frame,
               "median_gap_ms": statistics.median([h[2] for h in hitches]) if hitches else 0,
               "period_s": hper[0] if hper else None, "verdicts": dict(verdicts),
               "suspects": [{k: s[k] for k in ("kind", "label", "excess", "coverage", "false_rate")}
                            for s in suspects[:15]],
               "periodic": [{k: p[k] for k in ("kind", "name", "period", "bursts", "at_hitch", "regular")}
                            for p in periodic[:15]],
               "gt_cpu_ms_per_s": G["mi_gt"].get(A.exe_mid, 0) / dur_s if dur_s else 0}
    (folder / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    update_index(folder, summary, suspects, periodic)
    return rep


def file_label(owners, path):
    cat, label, short = owners.classify(path)
    if cat == "mod":
        return f"{short} ({label})"
    return short or path


def find_pid_in_trace(etl):
    rd = E.EtlReader(etl)
    found = {}

    def on_proc(ts, tid, pid, cpu, ver, op, d):
        if len(d) < 16:
            return
        p = _U32.unpack_from(d, 8)[0]
        off = E.skip_sid(d, 36 if ver >= 4 else 32)
        if off < len(d) and E.astr(d, off).lower() == GAME_EXE.lower():
            found[p] = True
    rd.on(E.G_PROCESS, (1, 3), on_proc)
    rd.run()
    if not found:
        raise SystemExit(f"{GAME_EXE} not found in the trace; pass --pid")
    return list(found)[-1]


def write_csvs(folder, per_hitch, mod_rows, periodic):
    if per_hitch:
        with (folder / "hitches.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(per_hitch[0].keys()))
            w.writeheader()
            w.writerows(per_hitch)
    with (folder / "modules.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["module", "category", "path", "leaf_ms", "leaf_ms_per_s", "leaf_gt_ms",
                                          "excl_ms", "incl_ms", "gt_incl_ms"])
        w.writeheader()
        for r in mod_rows:
            w.writerow({k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()})
    with (folder / "periodic.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["kind", "name", "period_s", "mad_s", "bursts", "at_hitch", "regular", "matches_hitch_period"])
        for p in periodic:
            w.writerow([p["kind"], p["name"], round(p["period"], 2), round(p["mad"], 2), p["bursts"], p["at_hitch"],
                        p["regular"], p["match"]])


def update_index(folder, summary, suspects, periodic):
    idx = OUT / "INDEX.md"
    line = (f"| [{folder.name}]({folder.name}/REPORT.md) | {summary['duration_s']:.0f} s | {summary['hitches']} | "
            f"{summary['hitches_per_min']:.1f} | {summary['median_gap_ms']:.0f} | "
            f"{summary['period_s']:.1f} s | " if summary["period_s"] else
            f"| [{folder.name}]({folder.name}/REPORT.md) | {summary['duration_s']:.0f} s | {summary['hitches']} | "
            f"{summary['hitches_per_min']:.1f} | {summary['median_gap_ms']:.0f} | - | ")
    line += (suspects[0]["label"].replace("|", "/") if suspects else "-") + " | "
    line += (periodic[0]["name"].replace("|", "/") + f" ({periodic[0]['period']:.1f} s)" if periodic else "-") + " |"
    head = ("# HitchWatch captures\n\n| Capture | Length | Hitches | per min | Median gap ms | Period | Top suspect | "
            "Top periodic source |\n|---|---|---|---|---|---|---|---|\n")
    rows = []
    if idx.is_file():
        rows = [ln for ln in idx.read_text(encoding="utf-8").splitlines()
                if ln.startswith("| [") and f"[{folder.name}]" not in ln]
    rows.append(line)
    rows.sort(reverse=True)
    tmp = idx.with_suffix(".tmp")
    tmp.write_text(head + "\n".join(rows) + "\n", encoding="utf-8")
    os.replace(tmp, idx)


def build_report(folder, cap, hdr, A, col, owners, hitches, med_frame, disp_only, per_hitch, verdicts, hper,
                 suspects, periodic, gtx, t_mi_gt, t_leaf_gt, t_leaf, t_mx, t_thr, t_wait, t_wby, t_wleaf, t_wthr,
                 t_proc, t_dpc, t_fw, t_fio, t_hf, t_rva, mod_rows, loaded_mods, G, total_ms, notes, fid, frames,
                 fnote, parse_s, rd, min_gap, ratio, extra, lead, n_normal):
    L = []
    w = L.append
    dur_s = total_ms / 1000.0
    w(f"# HitchWatch {folder.name}\n")
    w(f"HitchWatch {VERSION}. Trace {dur_s:.0f} s, game pid {col.game}, GameThread = "
      f"{'thread named GameThread' if A.gt_named else 'busiest game thread (no GameThread name found)'} "
      f"(tid {A.gt}). CPU sample interval {A.sample_ms:.2f} ms ({hdr['cpus']} CPUs). "
      f"Frames: {fnote}. Hitch = present gap >= max({ratio} x rolling median, median + {extra:.0f} ms, "
      f"{min_gap:.0f} ms); window = gap + {lead:.0f} ms before it.\n")
    for n in notes:
        w(f"> {n}\n")

    # ---------------------------------------------------------------- verdict
    w("## Verdict\n")
    if hitches:
        gaps = [h[2] for h in hitches]
        w(f"- **{len(hitches)} hitches** in {dur_s:.0f} s ({len(hitches) / dur_s * 60:.1f} per min). Gap median "
          f"{statistics.median(gaps):.0f} ms, max {max(gaps):.0f} ms; normal present interval {med_frame:.1f} ms.")
        if hper:
            p, mad, n = hper
            reg = "regular (timer-like)" if mad <= 0.2 * p else ("loosely regular" if mad <= 0.35 * p else
                                                                  "irregular")
            w(f"- Rhythm: one every **{p:.1f} s** (median spacing, MAD {mad:.1f} s) = {reg}.")
        w(f"- Where the time goes: " + ", ".join(f"{k} {v}x" for k, v in verdicts.most_common()) + ".")
    else:
        w("- No hitches found in the frame data" + (" (no PresentMon data)." if not frames else
                                                    f" with these thresholds (normal present interval "
                                                    f"{med_frame:.1f} ms). Try a lower --min-gap-ms."))
    if disp_only:
        w(f"- {len(disp_only)} display-only hitches (a frame stayed on screen long while presents kept coming): "
          "GPU / frame generation / display pacing, not CPU-side.")
    if suspects:
        w("\n**Top suspects** (extra cost during hitch windows over the normal rate; coverage = hitches where it "
          "was clearly above normal; false = normal windows where it was):\n")
        for i, s in enumerate(suspects[:10], 1):
            u = s["unit"]
            w(f"{i}. **{s['label']}** - {s['kind']}: +{fmt_ms(s['excess'])} {u} per hitch (normal "
              f"{fmt_ms(s['expected'])} {u} per window), in {s['coverage'] * 100:.0f}% of hitches, false "
              f"{s['false_rate'] * 100:.0f}%" + (f"  `{s['detail']}`" if s["detail"] else ""))
    elif hitches:
        w("\nNo module, process, driver, file or fault stands out during the hitches. If the verdict above says "
          "GameThread busy with only Cyberpunk2077.exe on the stack, it is engine or redscript work (see the hot "
          "exe offsets and the CET note below).")
    regular_match = [p for p in periodic if p["regular"] and (p["match"] or p["at_hitch"] >= 3)]
    if regular_match:
        w("\n**Sources with a fixed rhythm** (bursts at a steady interval):\n")
        for p in regular_match[:8]:
            w(f"- {p['kind']}: **{p['name']}** every {p['period']:.2f} s (MAD {p['mad']:.2f}), {p['bursts']} bursts"
              + (f", {p['at_hitch']} at a hitch" if hitches else "")
              + (" - **matches the hitch rhythm**" if p["match"] else ""))
    w("\n**How to act on it**\n")
    w("- A mod DLL (RED4ext plugin, ASI, CET) or a mod's file: disable that one mod in Vortex (or turn its logging "
      "off), record again, then `hitchwatch.py compare <old> <new>`.")
    w("- `no module` code on GameThread: CET LuaJIT (CET mods) or hook trampolines. Move half of the CET mods "
      "out with the game closed and record again.")
    w("- GameThread busy with only Cyberpunk2077.exe: engine or redscript work (redscript runs inside the exe). "
      "Compare the hot exe offsets between captures; bisect r6\\scripts mods.")
    w("- GameThread waiting on a render / driver thread, or `not GameThread`: GPU / present side (DLSS FG, "
      "ReShade / RenoDX, driver). Other process / DPC driver: close that program or update / disable that device.")

    # ---------------------------------------------------------------- per hitch
    if per_hitch:
        w("\n## Hitches\n")
        w("GT = GameThread ms inside the window (run / wait / ready-but-no-CPU). Extra = above the normal rate.\n")
        w("| Time | Gap ms | Normal | Verdict | GT run/wait/ready | Extra GameThread code ms | GT waited on (ms) | "
          "Woken by | Other process extra ms | Max DPC ms | File writes | GT hard faults |")
        w("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for p in per_hitch:
            w(f"| {p['time']} | {p['gap']:.0f} | {p['median']:.1f} | {p['verdict']} | {p['gt_run']:.0f}/"
              f"{p['gt_wait']:.0f}/{p['gt_ready']:.0f} of {p['win']:.0f} | {p['top_gt_code']} | {p['waited_on']} | "
              f"{p['woken_by']} | {p['other_proc']} | {p['dpc_max']} | {p['file_writes']} | "
              f"{p['hard_faults_gt']} |")

    def table(title, rows, keyfmt, unit="ms", note=""):
        if not rows:
            return
        w(f"\n### {title}\n")
        if note:
            w(note + "\n")
        w(f"| What | In hitch ({unit}) | Normal for that length | Extra | Coverage | False |")
        w("|---|---|---|---|---|---|")
        for r in rows:
            w(f"| {keyfmt(r['key'])} | {fmt_ms(r['hitch_mean'])} | {fmt_ms(r['expected'])} | "
              f"{'+' if r['excess'] >= 0 else ''}{fmt_ms(r['excess'])} | {r['coverage'] * 100:.0f}% | "
              f"{r['false_rate'] * 100:.0f}% |")

    if per_hitch:
        w("\n## During hitches vs normal frames\n")
        table("GameThread state", gtx, lambda k: k)
        table("GameThread wait reasons", t_wait,
              lambda k: f"{k}" + (f" ({WAIT_HINT[k]})" if k in WAIT_HINT else ""))
        table("Who woke GameThread", t_wby, lambda k: k)
        table("Work GameThread waited for (code the waking thread ran)", t_wleaf, A.mlabel,
              note="First mod module from the stack leaf, else the module the CPU was in.")
        table("Threads GameThread waited for (their CPU during the wait)", t_wthr, A.tlabel)
        table("Code on GameThread (first mod module on the stack, else the module the CPU was in)", t_leaf_gt,
              A.mlabel)
        table("Modules anywhere on GameThread's stack (inclusive, exe excluded)", t_mi_gt,
              lambda m: A.mlabel(m) + (" (wraps every GameThread tick)" if m in A.gt_wrapper_mods else ""),
              note="Inclusive: a module is counted when it is anywhere in the call stack. ntdll / kernel modules "
                   "and tick wrappers appear in most stacks, so read the other mod rows first.")
        table("CPU inside each module, all game threads (exclusive)", t_mx, A.mlabel)
        table("Code in the game process, all threads", t_leaf, A.mlabel)
        table("Game threads", t_thr, A.tlabel)
        table("Other processes", t_proc, col.proc_label)
        table("Driver DPC / ISR", t_dpc, A.mlabel)
        table("Files written by the game (ops)", t_fw, lambda k: file_label(owners, fid(*k)), unit="ops")
        table("GameThread file I/O time", t_fio, lambda k: file_label(owners, fid(*k)))
        table("GameThread hard page faults", t_hf, lambda k: k, unit="count / ms")
        table("Hot Cyberpunk2077.exe offsets on GameThread (RVA, 256-byte buckets)", t_rva, lambda k: f"exe+0x{k:x}",
              note="Engine or redscript code with no mod on the stack. Same offsets in two captures = same work.")

    # ---------------------------------------------------------------- periodic
    w("\n## Periodic sources\n")
    if periodic:
        w("Bursts = 25 ms bins far above that source's own average (mean + 4 sd). Regular = spacing MAD <= 25% of "
          "the period. Listed: regular sources, and irregular ones that burst mostly at hitches.\n")
        w("| Kind | Source | Every s | MAD s | Bursts | At a hitch | Regular | Matches hitch rhythm |")
        w("|---|---|---|---|---|---|---|---|")
        for p in periodic[:40]:
            w(f"| {p['kind']} | {p['name']} | {p['period']:.2f} | {p['mad']:.2f} | {p['bursts']} | "
              f"{p['at_hitch']} | {'yes' if p['regular'] else 'no'} | {'YES' if p['match'] else ''} |")
    else:
        w("No source with a steady rhythm found.")

    # ---------------------------------------------------------------- all modules
    w("\n## Every native module in the game process (whole capture)\n")
    w("`own` = CPU charged to the module: samples whose first mod module from the stack leaf is this one (so a "
      "plugin also owns the engine calls it makes), else the module the CPU was in. `GT` = the part on "
      "GameThread. `incl` = on the stack at all. CET counts all CET mods together; redscript is inside the exe.\n")
    w("| Module | Category | own ms/s | own GT ms | incl ms | Path |")
    w("|---|---|---|---|---|---|")
    for r in mod_rows:
        if r["leaf_ms"] < 0.5 * dur_s and r["category"] not in ("mod", "overlay"):
            continue
        w(f"| {r['module']} | {r['category']} | {r['leaf_ms_per_s']:.2f} | {r['leaf_gt_ms']:.0f} | "
          f"{r['incl_ms']:.0f} | `{r['path']}` |")
    idle = [lab for mid, (cat, lab, short) in loaded_mods if G["mi"].get(mid, 0) == 0]
    if idle:
        w(f"\nLoaded mod / overlay modules with no CPU sample at all ({len(idle)}): " + ", ".join(sorted(set(idle)))
          + ".")

    # ---------------------------------------------------------------- background processes
    pr0, pr1 = cap.get("procs_start") or {}, cap.get("procs_end") or {}
    rows = []
    for k, v in pr1.items():
        if k in pr0:
            dcpu = v["cpu_s"] - pr0[k]["cpu_s"]
            if dcpu > 0.05:
                rows.append((dcpu, v["name"], k))
    rows.sort(reverse=True)
    if rows:
        w("\n## Processes by CPU during the capture (psutil)\n")
        w("| Process | pid | CPU s | % of one core | Known poller / overlay |")
        w("|---|---|---|---|---|")
        for dcpu, name, k in rows[:25]:
            flag = "yes" if any(x in (name or "").lower() for x in KNOWN_POLLERS) else ""
            w(f"| {name} | {k} | {dcpu:.2f} | {dcpu / max(dur_s, 1) * 100:.1f} | {flag} |")
    known = sorted({v["name"] for v in pr1.values() if any(x in (v["name"] or "").lower() for x in KNOWN_POLLERS)})
    if known:
        w(f"\nKnown sensor pollers / overlays running: {', '.join(known)}.")

    # ---------------------------------------------------------------- method
    w("\n## Data quality\n")
    w(f"- Events {rd.total:,} parsed in {parse_s:.0f} s; game samples {len(col.g_ts):,} "
      f"(with stack {sum(1 for s in col.g_stk if s):,}); game context switches {len(col.cs_ts):,}; GameThread "
      f"segments {len(A.gt_segs):,}; DPC/ISR {len(col.d_end):,}; game file ops {len(col.f_ts):,}; game hard "
      f"faults {len(col.h_ts):,}; modules {len(col.mods) - 1}.")
    w(f"- Trace clock {hdr['clock']} at {hdr['perf_freq']:,} Hz; ETW lost {hdr.get('events_lost')} events / "
      f"{hdr.get('buffers_lost')} buffers; decode errors {rd.errors}.")
    w(f"- Baseline = whole-capture rates; false-alarm check on {n_normal} random windows away from hitches.")
    if A.gt_wrapper_mods:
        w("- Wrappers skipped when charging GameThread work: " + ", ".join(A.mlabel(m) for m in A.gt_wrapper_mods)
          + " (on GameThread's stack at a fixed depth in most samples, e.g. CET's main-loop tick hook).")
    rep = folder / "REPORT.md"
    tmp = rep.with_suffix(".tmp")
    tmp.write_text("\n".join(L) + "\n", encoding="utf-8")
    os.replace(tmp, rep)
    return rep


# ================================================================================================= compare
def compare(a, b):
    sa = json.loads((Path(a) / "summary.json").read_text(encoding="utf-8"))
    sb = json.loads((Path(b) / "summary.json").read_text(encoding="utf-8"))
    print(f"{'':28} {sa['folder']:>22} {sb['folder']:>22}")
    for k, lab in (("duration_s", "length s"), ("hitches", "hitches"), ("hitches_per_min", "hitches per min"),
                   ("median_gap_ms", "median gap ms"), ("period_s", "rhythm s"), ("median_frame_ms", "normal frame ms"),
                   ("gt_cpu_ms_per_s", "GameThread CPU ms/s")):
        va, vb = sa.get(k), sb.get(k)
        fa = f"{va:.1f}" if isinstance(va, (int, float)) else str(va)
        fb = f"{vb:.1f}" if isinstance(vb, (int, float)) else str(vb)
        print(f"{lab:28} {fa:>22} {fb:>22}")
    for s, name in ((sa, sa["folder"]), (sb, sb["folder"])):
        print(f"\nTop suspects {name}:")
        for x in s["suspects"][:6]:
            print(f"  {x['label']} ({x['kind']}): +{x['excess']:.1f} per hitch, {x['coverage'] * 100:.0f}%")
        print(f"Periodic {name}:")
        for x in s["periodic"][:6]:
            print(f"  {x['kind']} {x['name']}: every {x['period']:.2f} s, {x['bursts']} bursts, {x['at_hitch']} at hitch")


# ================================================================================================= main
def main():
    ap = argparse.ArgumentParser(description="HitchWatch: find what causes periodic frame hitches")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("record", help="record (admin), then analyse")
    r.add_argument("--seconds", type=int, default=60)
    r.add_argument("--delay", type=int, default=10, help="countdown before recording starts")
    r.add_argument("--wait", type=int, default=30, help="minutes to wait for the game to start")
    r.add_argument("--no-analyze", action="store_true")
    r.add_argument("--frames-only", action="store_true",
                   help="PresentMon only, no kernel trace: frame pacing / microstutter report FRAMES.md")
    fr = sub.add_parser("frames", help="frame pacing report (FRAMES.md) for a capture folder with frames.csv")
    fr.add_argument("folder")
    fr.add_argument("--pid", type=int)
    for p in (r, sub.add_parser("analyze", help="analyse a capture folder")):
        p.add_argument("--min-gap-ms", type=float, default=25.0, help="smallest present gap that counts as a hitch")
        p.add_argument("--ratio", type=float, default=2.5, help="hitch = gap >= ratio x rolling median")
        p.add_argument("--extra-ms", type=float, default=18.0, help="and gap >= median + this")
        p.add_argument("--lead-ms", type=float, default=60.0, help="window starts this long before the gap")
        p.add_argument("--pid", type=int)
    an = sub.choices["analyze"]
    an.add_argument("folder", nargs="?")
    an.add_argument("--latest", action="store_true")
    c = sub.add_parser("compare", help="compare two capture folders")
    c.add_argument("a")
    c.add_argument("b")
    args = ap.parse_args()
    if args.cmd == "record":
        return record(args)
    if args.cmd == "analyze":
        if args.latest or not args.folder:
            caps = sorted([d for d in OUT.iterdir() if d.is_dir() and (d / "trace.etl").is_file()],
                          key=lambda d: d.name) if OUT.is_dir() else []
            if not caps:
                raise SystemExit("no capture with trace.etl in " + str(OUT))
            folder = caps[-1]
        else:
            folder = Path(args.folder)
            if not folder.is_absolute() and not folder.exists():
                folder = OUT / args.folder
        calm_self()
        print(analyze(folder, args))
        return 0
    if args.cmd == "frames":
        folder = Path(args.folder)
        folder = folder if folder.exists() else OUT / args.folder
        print(frames_report(folder, args.pid))
        return 0
    if args.cmd == "compare":
        fa, fb = Path(args.a), Path(args.b)
        fa = fa if fa.exists() else OUT / args.a
        fb = fb if fb.exists() else OUT / args.b
        compare(fa, fb)
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
