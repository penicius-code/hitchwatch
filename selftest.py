"""HitchWatch self-test: synthetic kernel events through the real Collector / Analysis / report.

Plants a RED4ext plugin ("TestPlugin.dll") that, every 5 s, runs 45 ms on GameThread and writes a log file, plus
a background process with a 2 s rhythm unrelated to hitches. Expects TestPlugin as top suspect and a 5 s rhythm.
Run: python -I -X utf8 selftest.py
"""
import json
import random
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import etwfile as E  # noqa: E402
import hitchwatch as H  # noqa: E402

FREQ = 10_000_000
T0 = 5_000_000_000
GAME, OTHER = 1000, 2000
GT, RT, WK, OT = 10, 11, 12, 20
DEV = next((d.rstrip("\\") for d, L in H.dos_map() if L.upper() == str(H.GAME_DIR)[:3].upper()),
           r"\Device\HarddiskVolume3")
GAMEREL = DEV + str(H.GAME_DIR)[2:]
EXE_B, CET_B, PLG_B, NTDLL_B = 0x140000000, 0x7FF800000000, 0x7FF810000000, 0x7FFA00000000
KRN_B, NV_B = 0xFFFFF80000000000, 0xFFFFF80100000000


def wz(s):
    return s.encode("utf-16-le") + b"\0\0"


def ev_process(pid, name):
    d = struct.pack("<QIIIiQI", 0, pid, 4, 1, 0, 0, 0) + struct.pack("<I", 0) + name.encode() + b"\0" + wz(name)
    return (E.G_PROCESS, 3, 4, d)


def ev_thread(pid, tid, start):
    d = struct.pack("<II", pid, tid) + struct.pack("<6Q", 0, 0, 0, 0, 0, start) + struct.pack("<QI4B", 0, 0, 8, 5, 2, 0)
    return (E.G_THREAD, 3, 3, d)


def ev_tname(pid, tid, name):
    return (E.G_THREAD, 72, 2, struct.pack("<II", pid, tid) + wz(name))


def ev_image(pid, base, size, path):
    d = struct.pack("<QQIIIIQIIII", base, size, pid, 0, 0, 0, base, 0, 0, 0, 0) + wz(path)
    return (E.G_IMAGE, 3, 3, d)


def ev_sample(ip, tid):
    return (E.G_PERFINFO, 46, 2, struct.pack("<QIHH", ip, tid, 1, 0))


def ev_stack(ets, pid, tid, frames):
    return (E.G_STACKWALK, 32, 2, struct.pack("<QII", ets, pid, tid) + struct.pack(f"<{len(frames)}Q", *frames))


def ev_cswitch(new, old, reason=6, state=5):
    d = bytearray(struct.pack("<II", new, old) + bytes(8) + struct.pack("<II", 0, 0))
    d[12], d[14] = reason, state
    return (E.G_THREAD, 36, 4, bytes(d))


def ev_ready(tid):
    return (E.G_THREAD, 50, 2, struct.pack("<IBBBB", tid, 0, 0, 0, 0))


def ev_dpc(init, routine):
    return (E.G_PERFINFO, 68, 2, struct.pack("<QQ", init, routine))


def ev_fcreate(irp, fo, tid, path):
    return (E.G_FILEIO, 64, 3, struct.pack("<QQIIII", irp, fo, tid, 0, 0, 0) + wz(path))


def ev_fwrite(irp, fo, tid, size):
    return (E.G_FILEIO, 68, 3, struct.pack("<QQQQIII", 0, irp, fo, fo + 1, tid, size, 0))


def ev_fend(irp):
    return (E.G_FILEIO, 76, 3, struct.pack("<QQI", irp, 0, 0))


class FakeReader(E.EtlReader):
    def __init__(self, path, events):
        super().__init__(path)
        self.events = events

    def run(self):
        self.header = {"perf_freq": FREQ, "clock_type": 1, "clock": "QPC", "start_filetime": 0, "end_filetime": 0,
                       "boot_filetime": 0, "cpus": 4, "pointer_size": 8, "events_lost": 0, "buffers_lost": 0,
                       "events_lost_read": 0}
        for ts, tid, pid, cpu, (guid, op, ver, d) in self.events:
            self.total += 1
            h = self.handlers.get((guid, op))
            if h:
                self.handled += 1
                try:
                    h(ts, tid, pid, cpu, ver, op, d)
                except Exception as e:
                    self.errors += 1
                    import traceback
                    self.first_errors.append("".join(traceback.format_exception(e)))
        return self.header


def build(seconds=40):
    rnd = random.Random(1)
    ev = []
    t = T0 - 1000

    def add(ts, e, tid=0, pid=0, cpu=0):
        ev.append((ts, tid, pid, cpu, e))
    add(t, ev_process(GAME, "Cyberpunk2077.exe"))
    add(t, ev_process(OTHER, "HWiNFO64.exe"))
    for tid, pid, st in ((GT, GAME, EXE_B + 0x100), (RT, GAME, EXE_B + 0x200), (WK, GAME, PLG_B + 0x10),
                         (OT, OTHER, 0x400000)):
        add(t, ev_thread(pid, tid, st))
    add(t, ev_tname(GAME, GT, "GameThread"))
    add(t, ev_tname(GAME, RT, "RenderThread"))
    add(t, ev_image(GAME, EXE_B, 0x8000000, GAMEREL + r"\bin\x64\Cyberpunk2077.exe"))
    add(t, ev_image(GAME, CET_B, 0x1000000, GAMEREL + r"\bin\x64\plugins\cyber_engine_tweaks.asi"))
    add(t, ev_image(GAME, PLG_B, 0x100000, GAMEREL + r"\red4ext\plugins\TestPlugin\TestPlugin.dll"))
    add(t, ev_image(GAME, NTDLL_B, 0x200000, r"\SystemRoot\System32\ntdll.dll"))
    add(t, ev_image(0, KRN_B, 0x1000000, r"\SystemRoot\system32\ntoskrnl.exe"))
    add(t, ev_image(0, NV_B, 0x1000000, r"\SystemRoot\System32\DriverStore\FileRepository\nv_dispi.inf_amd64\nvlddmkm.sys"))
    ms = FREQ // 1000
    hitch_starts = [T0 + int((2.3 + 5.0 * k) * FREQ) for k in range(int(seconds / 5))]
    in_hitch = lambda ts: any(h <= ts < h + 45 * ms for h in hitch_starts)  # noqa: E731
    root = [NTDLL_B + 0x50, EXE_B + 0x10]  # thread root
    cet_tick = [CET_B + 0x777]              # CET main-loop wrapper at a fixed depth
    irp = 1
    for i in range(seconds * 1000):
        ts = T0 + i * ms
        # GameThread: always running in this test; normal = exe under CET's tick hook; hitch = TestPlugin code
        if in_hitch(ts):
            ip = PLG_B + 0x400 + rnd.randint(0, 64)
            frames = [ip, EXE_B + 0x9000, PLG_B + 0x500, EXE_B + 0x3000] + cet_tick + [EXE_B + 0x2000] + root
        else:
            ip = EXE_B + 0x5000 + rnd.randint(0, 0x4000)
            frames = [ip, EXE_B + 0x3000] + cet_tick + [EXE_B + 0x2000] + root
        add(ts, ev_sample(ip, GT), cpu=0)
        add(ts, ev_stack(ts, GAME, GT, frames), cpu=0)
        # render thread
        if i % 2 == 0:
            ip = EXE_B + 0x20000 + rnd.randint(0, 0x100)
            add(ts + 1, ev_sample(ip, RT), cpu=1)
            add(ts + 1, ev_stack(ts + 1, GAME, RT, [ip, EXE_B + 0x21000] + root), cpu=1)
        # other process: 2 s rhythm, bursts unrelated to hitches
        if (i % 2000) < 30:
            add(ts + 2, ev_sample(0x400100, OT), cpu=2)
        # DPC noise
        if i % 3 == 0:
            add(ts + 3, ev_dpc(ts + 3 - 200, NV_B + 0x100), cpu=3)
        # GameThread waits 2 ms every 10 ms when not in a hitch (woken by the render thread)
        if i % 10 == 0 and not in_hitch(ts):
            add(ts + 5, ev_cswitch(RT, GT, reason=37, state=5), cpu=0)
            add(ts + 2 * ms, ev_ready(GT), tid=RT, pid=GAME, cpu=1)
            add(ts + 2 * ms + 1, ev_cswitch(GT, RT), cpu=0)
        # plugin writes its log during hitches
        if in_hitch(ts) and i % 5 == 0:
            add(ts + 4, ev_fcreate(irp, 0xABC0, GT, GAMEREL + r"\r6\storages\TestPlugin\log.txt"), tid=GT)
            add(ts + 4, ev_stack(ts + 4, GAME, GT, [NTDLL_B + 0x99, PLG_B + 0x600, EXE_B + 0x3000] + cet_tick + root))
            add(ts + 5, ev_fwrite(irp + 1, 0xABC0, GT, 4096), tid=GT)
            add(ts + 5, ev_stack(ts + 5, GAME, GT, [NTDLL_B + 0x98, PLG_B + 0x600, EXE_B + 0x3000] + cet_tick + root))
            add(ts + 3 * ms, ev_fend(irp + 1))
            irp += 2
    ev.sort(key=lambda e: e[0])
    # frames: 6 ms presents, the frame after each hitch start arrives 55 ms late
    rows = []
    q = T0
    hs = sorted(hitch_starts)
    while q < T0 + seconds * FREQ:
        rows.append(q)
        nxt = q + 6 * ms
        for h in hs:
            if q <= h < nxt:
                nxt = h + 55 * ms
        q = nxt
    return ev, rows, hitch_starts


def main():
    ev, rows, hs = build()
    folder = Path(tempfile.mkdtemp(prefix="hitchwatch-selftest-"))
    (folder / "trace.etl").write_bytes(b"fake")
    with (folder / "frames.csv").open("w", encoding="utf-8") as f:
        f.write("Application,ProcessID,SwapChainAddress,CPUStartQPC,MsCPUBusy,MsGPUTime,MsDisplayedTime\n")
        prev = rows[0]
        for q in rows:
            f.write(f"Cyberpunk2077.exe,{GAME},0x1,{q},5.0,5.0,{(q - prev) / 10000:.3f}\n")
            prev = q
    cap = {"pid": GAME, "anchor_start": {"qpc": T0, "filetime": 0, "unix": 1_800_000_000.0}, "qpc_freq": FREQ,
           "threads_start": {}, "threads_end": {}, "procs_start": {}, "procs_end": {}}
    (folder / "capture.json").write_text(json.dumps(cap), encoding="utf-8")
    orig = H.E.EtlReader
    H.E.EtlReader = lambda path: FakeReader(path, ev)
    H.OUT = folder.parent / "hitchwatch-selftest-index"
    H.OUT.mkdir(exist_ok=True)
    try:
        rep = H.analyze(folder)
    finally:
        H.E.EtlReader = orig
    text = Path(rep).read_text(encoding="utf-8")
    s = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
    ok = True

    def check(cond, what):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + what)
        ok &= bool(cond)
    check(s["hitches"] == len(hs), f"hitches found {s['hitches']} (planted {len(hs)})")
    check(s["period_s"] and abs(s["period_s"] - 5.0) < 0.2, f"rhythm {s['period_s']}")
    top = s["suspects"][0]["label"] if s["suspects"] else ""
    check("TestPlugin" in top, f"top suspect = {top}")
    check(any("TestPlugin" in x["label"] and "log.txt" in x["label"] for x in s["suspects"]), "log file write suspect")
    check(not any("cyber_engine_tweaks" in x["label"].lower() or "CET" in x["label"] for x in s["suspects"][:3]),
          "CET wrapper not blamed")
    check(any(p["kind"] == "process" and "HWiNFO" in p["name"] and abs(p["period"] - 2.0) < 0.2
              for p in s["periodic"]), "2 s background process rhythm found")
    check(any("TestPlugin" in p["name"] and p["regular"] for p in s["periodic"]), "TestPlugin periodic")
    check(list(s["verdicts"]) == ["GameThread busy: TestPlugin [TestPlugin.dll]"], f"verdicts {s['verdicts']}")
    check("TestPlugin" in s["suspects"][0]["label"] and "[TestPlugin.dll]" in s["suspects"][0]["label"],
          "plugin labelled from its red4ext folder")
    if ok and "--keep" not in sys.argv:
        import shutil
        shutil.rmtree(folder, ignore_errors=True)
        shutil.rmtree(H.OUT, ignore_errors=True)
        print("\nall passed (temp folder removed; --keep keeps the report)")
    else:
        print(f"\nreport: {rep}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
