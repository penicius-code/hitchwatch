"""Frame pacing / microstutter report from a PresentMon 2.x frames.csv (HitchWatch --frames-only or any capture).

Microstutter = uneven spacing of the frames that reach the screen, usually 5-30 ms off, far below a hitch. Three
views from PresentMon's own columns:
  - displayed frames (MsBetweenDisplayChange): what the eye sees, generated frames (DLSS FG) included
  - game frames (FrameType Application, MsBetweenAppStart / MsBetweenPresents, MsCPUBusy, MsGPUBusy): what the
    engine renders; uneven game frames come through as uneven displayed frames
  - MsAnimationError: how far the motion shown differs from the time between displays (judder even at even spacing)
usage: framepacing.py FOLDER [--pid N]   (writes FOLDER\\FRAMES.md)"""
import collections
import csv
import statistics
import sys
from pathlib import Path


def _num(v):
    try:
        x = float(v)
        return x if x == x else None
    except (TypeError, ValueError):
        return None


def _pct(vals, q):
    if not vals:
        return 0.0
    s = sorted(vals)
    return s[min(len(s) - 1, int(q * (len(s) - 1) + 0.5))]


def _norm(name):
    n = name.strip().lower()
    return n[2:] if n.startswith("ms") else n


def _col(hdr, *names):
    """Column by name; PresentMon writes 'MsCPUBusy' or 'CPUBusy' depending on version / --v2_metrics."""
    low = {_norm(h): h for h in hdr}
    for n in names:
        if _norm(n) in low:
            return low[_norm(n)]
    return None


def _pacing(vals, label):
    """Stats for a list of intervals (ms) in order."""
    if len(vals) < 20:
        return [f"- {label}: too few samples ({len(vals)})"], {}
    med = statistics.median(vals)
    dev = [abs(v - med) for v in vals]
    off25 = sum(1 for v in vals if abs(v - med) > 0.25 * med)
    jumps = [abs(b - a) for a, b in zip(vals, vals[1:])]
    alt = sum(1 for a, b in zip(vals, vals[1:]) if (a < 0.75 * med and b > 1.25 * med) or (a > 1.25 * med and b < 0.75 * med))
    st = {"n": len(vals), "median": med, "p95": _pct(vals, 0.95), "p99": _pct(vals, 0.99), "max": max(vals),
          "mad": statistics.median(dev), "off25": off25 / len(vals), "jump_p95": _pct(jumps, 0.95), "alt": alt / len(vals)}
    lines = [f"- {label}: {len(vals)} intervals, median {med:.2f} ms ({1000 / med:.0f} fps), p95 {st['p95']:.2f}, "
             f"p99 {st['p99']:.2f}, max {st['max']:.1f} ms",
             f"  - spread: median deviation {st['mad']:.2f} ms; {100 * st['off25']:.1f} % of intervals more than 25 % off "
             f"the median; frame-to-frame change p95 {st['jump_p95']:.2f} ms; short/long alternation {100 * st['alt']:.1f} %"]
    return lines, st


def frames_report(folder, pid=None):
    folder = Path(folder)
    out = folder / "FRAMES.md"
    lines = [f"# Frame pacing {folder.name}", ""]
    path = None
    for name in ("frames.csv", "frames_app.csv"):  # frames_app.csv = minimal session (no display tracking)
        c = folder / name
        if c.is_file() and c.stat().st_size > 0 and sum(1 for _ in c.open(encoding="utf-8-sig", errors="replace")) > 50:
            path = c
            break
    if path is None:
        lines.append("frames.csv / frames_app.csv missing or empty: PresentMon wrote nothing (see presentmon_stderr in capture.json).")
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
        rd = csv.DictReader(f)
        hdr = rd.fieldnames or []
        rows = list(rd)
    c_pid = _col(hdr, "ProcessID")
    c_app = _col(hdr, "Application")
    c_sc = _col(hdr, "SwapChainAddress")
    if pid is None and c_pid and rows:
        games = [r for r in rows if c_app and "cyberpunk2077" in (r.get(c_app) or "").lower()]
        pid = collections.Counter(r[c_pid] for r in (games or rows)).most_common(1)[0][0]
    all_rows = rows
    if c_pid and pid is not None:
        rows = [r for r in rows if str(r.get(c_pid, "")).strip() == str(pid)]
        if not rows and c_app:  # the game's presents under another pid (frames_app.csv records every process)
            rows = [r for r in all_rows if "cyberpunk2077" in (r.get(c_app) or "").lower()]
    if not rows and all_rows:
        seen = collections.Counter(((r.get(c_app) or "?"), (r.get(c_pid) or "?")) for r in all_rows)
        lines.append(f"No presents for the game (pid {pid}) in {path.name}. Processes that presented: "
                     + ", ".join(f"{a} (pid {p}) {n}" for (a, p), n in seen.most_common(10)))
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out
    if c_sc and rows:
        sc = collections.Counter(r[c_sc] for r in rows).most_common(1)[0][0]
        rows = [r for r in rows if r[c_sc] == sc]
    if not rows:
        lines.append("No frames for the game in frames.csv.")
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out
    c_type = _col(hdr, "FrameType")
    c_disp = _col(hdr, "MsBetweenDisplayChange", "DisplayedTime")
    c_app_iv = _col(hdr, "MsBetweenAppStart", "FrameTime", "MsBetweenSimulationStart", "MsBetweenPresents")
    c_cpu = _col(hdr, "MsCPUBusy")
    c_cwait = _col(hdr, "MsCPUWait")
    c_gpu = _col(hdr, "MsGPUBusy", "MsGPUTime")
    c_anim = _col(hdr, "MsAnimationError")
    c_mode = _col(hdr, "PresentMode")
    c_lat = _col(hdr, "MsPCLatency", "MsClickToPhotonLatency")
    types = collections.Counter((r.get(c_type) or "?").strip() for r in rows) if c_type else collections.Counter()
    app_rows = [r for r in rows if not c_type or (r.get(c_type) or "").strip().lower() in ("application", "app", "")]
    disp = [v for v in (_num(r.get(c_disp)) for r in rows) if v and v > 0] if c_disp else []
    app_iv = [v for v in (_num(r.get(c_app_iv)) for r in app_rows) if v and v > 0] if c_app_iv else []
    cpu = [v for v in (_num(r.get(c_cpu)) for r in app_rows) if v is not None] if c_cpu else []
    cwait = [v for v in (_num(r.get(c_cwait)) for r in app_rows) if v is not None] if c_cwait else []
    gpu = [v for v in (_num(r.get(c_gpu)) for r in app_rows) if v is not None] if c_gpu else []
    anim = [abs(v) for v in (_num(r.get(c_anim)) for r in rows) if v is not None] if c_anim else []
    lat = [v for v in (_num(r.get(c_lat)) for r in app_rows) if v and v > 0] if c_lat else []
    fg_note = ""
    if not c_type and c_app_iv and len(app_iv) > 50 and statistics.median(app_iv) < 0.4 * _pct(app_iv, 0.9):
        # no FrameType column (older PresentMon) but frame generation on: generated presents come right after the
        # real one (tiny interval, ~0.5 ms CPU). A real game frame = a present with a long interval; its game-frame
        # interval is the time since the previous real one.
        thr = 0.3 * _pct(app_iv, 0.9)
        acc, gi, gc, gg, n_real = 0.0, [], [], [], 0
        for r in app_rows:
            v = _num(r.get(c_app_iv))
            if not v or v <= 0:
                continue
            acc += v
            if v >= thr:
                n_real += 1
                gi.append(acc)
                acc = 0.0
                if c_cpu and _num(r.get(c_cpu)) is not None:
                    gc.append(_num(r.get(c_cpu)))
                if c_gpu and _num(r.get(c_gpu)) is not None:
                    gg.append(_num(r.get(c_gpu)))
        fg_note = (f" Frame generation detected without a FrameType column: {n_real} real game frames of "
                   f"{len(app_iv)} presents (~{len(app_iv) / max(n_real, 1):.1f}x), split by interval >= {thr:.1f} ms.")
        app_iv, cpu, gpu = gi[1:], gc[1:], gg[1:]
        cwait = []
    secs = sum(app_iv) / 1000 if app_iv else 0
    lines += [f"Source: {path.name}" + (" (display tracking off: no displayed-frame pacing, game-frame cadence only)"
                                        if path.name == "frames_app.csv" else ""), ""]
    lines += [f"{len(rows)} presents of pid {pid} ({secs:.0f} s of game frames). Frame types: "
              + (", ".join(f"{k} {v}" for k, v in types.most_common()) if types else "no FrameType column")
              + (f". Present mode: {collections.Counter(r.get(c_mode) for r in rows).most_common(1)[0][0]}" if c_mode else "") + "." + fg_note, ""]
    lines += ["## Pacing", ""]
    dl, ds = _pacing(disp, "Displayed frames (what reaches the screen, generated frames included)")
    al, as_ = _pacing(app_iv, "Game frames (rendered by the engine)")
    lines += dl + al
    if cpu and gpu:
        lines.append(f"- game frame work: CPU busy median {statistics.median(cpu):.1f} / p99 {_pct(cpu, 0.99):.1f} ms, "
                     f"GPU busy median {statistics.median(gpu):.1f} / p99 {_pct(gpu, 0.99):.1f} ms"
                     + (f", CPU waiting median {statistics.median(cwait):.1f} ms" if cwait else ""))
    if anim:
        lines.append(f"- animation error (motion shown vs display spacing): mean {statistics.mean(anim):.2f} ms, "
                     f"p95 {_pct(anim, 0.95):.2f}, p99 {_pct(anim, 0.99):.2f}, max {max(anim):.1f} ms")
    if lat:
        lines.append(f"- PC latency median {statistics.median(lat):.1f} ms, p99 {_pct(lat, 0.99):.1f} ms")
    # verdict
    lines += ["", "## Reading", ""]
    if as_ and ds:
        bound = ""
        if cpu and gpu:
            bound = "GPU-bound" if statistics.median(gpu) > 0.85 * as_["median"] else (
                "CPU-bound" if statistics.median(cpu) > 0.85 * as_["median"] else "neither saturated (waits / sync)")
        lines.append(f"- Game frames are {bound}: GPU busy is {statistics.median(gpu):.1f} of {as_['median']:.1f} ms." if bound else "")
        if as_["off25"] >= 0.05:
            lines.append(f"- The game frames themselves are uneven ({100 * as_['off25']:.0f} % more than 25 % off): the "
                         "stutter starts in the engine / mods, frame generation only repeats it. Spikes below show when.")
        else:
            lines.append("- Game frames are even: the engine is not the source of the unevenness.")
        if ds["off25"] >= 0.05 and as_["off25"] < 0.05:
            lines.append("- Displayed frames are uneven while game frames are even: frame generation / present pacing "
                         "(DLSS FG, RenoDX / OptiScaler chain, VRR / V-Sync limits) is the source.")
        if ds["alt"] >= 0.03:
            lines.append(f"- {100 * ds['alt']:.0f} % short/long alternation on screen: classic frame-generation pacing "
                         "judder (generated frame shown too early or late), most visible on slow camera pans.")
        if anim and _pct(anim, 0.95) > 0.25 * (ds["median"] if ds else 1):
            lines.append("- Animation error p95 is over a quarter of a displayed frame: motion steps are uneven even "
                         "where the spacing looks fine (sim time vs present time mismatch).")
    # spikes over time
    if app_iv:
        med = statistics.median(app_iv)
        t, spikes = 0.0, []
        for v in app_iv:
            t += v / 1000
            if v > 1.5 * med and v > med + 8:
                spikes.append((t, v))
        lines += ["", f"## Game-frame spikes (> 1.5x median and +8 ms): {len(spikes)} = {len(spikes) / max(secs / 60, 0.01):.0f}/min", ""]
        if spikes:
            gaps = [b[0] - a[0] for a, b in zip(spikes, spikes[1:])]
            if len(gaps) >= 4:
                lines.append(f"- spacing between spikes: median {statistics.median(gaps):.2f} s "
                             f"(a steady spacing points at a periodic job: a mod timer, autosave, a poller)")
            lines.append("- worst: " + ", ".join(f"{v:.0f} ms at {tt:.1f} s" for tt, v in sorted(spikes, key=lambda x: -x[1])[:12]))
    lines.append("")
    out.write_text("\n".join(l for l in lines if l is not None) + "\n", encoding="utf-8")
    return out


if __name__ == "__main__":
    a = sys.argv[1:]
    p = None
    if "--pid" in a:
        i = a.index("--pid")
        p = a[i + 1]
        del a[i:i + 2]
    print(frames_report(a[0], p))
