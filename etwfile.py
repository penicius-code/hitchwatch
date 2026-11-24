"""etwfile.py - read Windows kernel (classic MOF) events from an .etl file. Part of HitchWatch.

Pure ctypes over advapi32 OpenTraceW / ProcessTrace, no external tools, read-only (never starts or stops a trace).
Timestamps stay raw (PROCESS_TRACE_MODE_RAW_TIMESTAMP): with WPR's default QPC clock they are the same numbers
PresentMon prints with --qpc_time, and they match the EventTimeStamp inside StackWalk events exactly.

Payload layouts are the x64 kernel layouts as decoded by Microsoft's TraceEvent library (PerfView); newer event
versions only append fields, so prefix offsets stay valid. Every decoder checks the payload length first.
"""
import ctypes as C
import struct
import uuid

_adv = C.WinDLL("advapi32", use_last_error=True)


class GUID(C.Structure):
    _fields_ = [("Data1", C.c_uint32), ("Data2", C.c_uint16), ("Data3", C.c_uint16), ("Data4", C.c_ubyte * 8)]


class EVENT_TRACE_HEADER(C.Structure):
    _fields_ = [("Size", C.c_ushort), ("FieldTypeFlags", C.c_ushort), ("Version", C.c_ulong),
                ("ThreadId", C.c_ulong), ("ProcessId", C.c_ulong), ("TimeStamp", C.c_longlong),
                ("Guid", GUID), ("ProcessorTime", C.c_ulonglong)]


class EVENT_TRACE(C.Structure):
    _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", C.c_ulong), ("ParentInstanceId", C.c_ulong),
                ("ParentGuid", GUID), ("MofData", C.c_void_p), ("MofLength", C.c_ulong),
                ("ClientContext", C.c_ulong)]


class SYSTEMTIME(C.Structure):
    _fields_ = [(n, C.c_ushort) for n in ("wYear", "wMonth", "wDayOfWeek", "wDay", "wHour", "wMinute",
                                          "wSecond", "wMilliseconds")]


class TIME_ZONE_INFORMATION(C.Structure):
    _fields_ = [("Bias", C.c_long), ("StandardName", C.c_wchar * 32), ("StandardDate", SYSTEMTIME),
                ("StandardBias", C.c_long), ("DaylightName", C.c_wchar * 32), ("DaylightDate", SYSTEMTIME),
                ("DaylightBias", C.c_long)]


class TRACE_LOGFILE_HEADER(C.Structure):
    _fields_ = [("BufferSize", C.c_ulong), ("Version", C.c_ulong), ("ProviderVersion", C.c_ulong),
                ("NumberOfProcessors", C.c_ulong), ("EndTime", C.c_longlong), ("TimerResolution", C.c_ulong),
                ("MaximumFileSize", C.c_ulong), ("LogFileMode", C.c_ulong), ("BuffersWritten", C.c_ulong),
                ("StartBuffers", C.c_ulong), ("PointerSize", C.c_ulong), ("EventsLost", C.c_ulong),
                ("CpuSpeedInMHz", C.c_ulong), ("LoggerName", C.c_void_p), ("LogFileName", C.c_void_p),
                ("TimeZone", TIME_ZONE_INFORMATION), ("BootTime", C.c_longlong), ("PerfFreq", C.c_longlong),
                ("StartTime", C.c_longlong), ("ReservedFlags", C.c_ulong), ("BuffersLost", C.c_ulong)]


EVENT_RECORD_CALLBACK = C.WINFUNCTYPE(None, C.c_void_p)
BUFFER_CALLBACK = C.WINFUNCTYPE(C.c_ulong, C.c_void_p)


class EVENT_TRACE_LOGFILEW(C.Structure):
    _fields_ = [("LogFileName", C.c_wchar_p), ("LoggerName", C.c_wchar_p), ("CurrentTime", C.c_longlong),
                ("BuffersRead", C.c_ulong), ("ProcessTraceMode", C.c_ulong), ("CurrentEvent", EVENT_TRACE),
                ("LogfileHeader", TRACE_LOGFILE_HEADER), ("BufferCallback", BUFFER_CALLBACK),
                ("BufferSize", C.c_ulong), ("Filled", C.c_ulong), ("EventsLost", C.c_ulong),
                ("EventRecordCallback", EVENT_RECORD_CALLBACK), ("IsKernelTrace", C.c_ulong),
                ("Context", C.c_void_p)]


assert C.sizeof(EVENT_TRACE) == 88 and C.sizeof(TRACE_LOGFILE_HEADER) == 280, "ETW struct layout mismatch"
assert C.sizeof(EVENT_TRACE_LOGFILEW) == 448, "EVENT_TRACE_LOGFILEW layout mismatch"

_adv.OpenTraceW.restype = C.c_uint64
_adv.OpenTraceW.argtypes = [C.POINTER(EVENT_TRACE_LOGFILEW)]
_adv.ProcessTrace.restype = C.c_ulong
_adv.ProcessTrace.argtypes = [C.POINTER(C.c_uint64), C.c_ulong, C.c_void_p, C.c_void_p]
_adv.CloseTrace.restype = C.c_ulong
_adv.CloseTrace.argtypes = [C.c_uint64]

INVALID_HANDLE = 0xFFFFFFFFFFFFFFFF
MODE_EVENT_RECORD = 0x10000000
MODE_RAW_TIMESTAMP = 0x00001000
CLOCK_NAMES = {1: "QPC", 2: "SystemTime", 3: "CPUCycle"}


def _g(s):
    return uuid.UUID(s).bytes_le


# Classic kernel event classes (EVENT_RECORD.ProviderId = class GUID, Opcode = event type)
G_PROCESS = _g("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c")
G_THREAD = _g("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c")
G_PAGEFAULT = _g("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c")
G_DISKIO = _g("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c")
G_IMAGE = _g("2cb15d1d-5fc1-11d2-abe1-00a0c911f518")
G_PERFINFO = _g("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc")
G_STACKWALK = _g("def2fe46-7bd6-4b80-bd94-f57fe20d0ce3")
G_FILEIO = _g("90cbdc39-4a3e-11d1-84f4-0000f80464e3")

# EVENT_RECORD prefix: Flags, ThreadId, ProcessId, TimeStamp, ProviderId, Version, Opcode,
# BufferContext.ProcessorNumber, UserDataLength, UserData
HDR = struct.Struct("<4xH2xIIq16s2xB2xB34xB5xH8xQ")
assert HDR.size == 104


def wstr(d, off):
    """Null-terminated UTF-16LE string starting at off."""
    end = off
    while True:
        end = d.find(b"\0\0", end)
        if end < 0:
            end = len(d)
            break
        if (end - off) % 2 == 0:
            break
        end += 1
    return d[off:end].decode("utf-16-le", "replace")


def astr(d, off):
    end = d.find(b"\0", off)
    return d[off:end if end >= 0 else len(d)].decode("latin-1")


def skip_sid(d, off, ptr=8):
    """WBEMSID: 4 zero bytes when absent, else TOKEN_USER (2 pointers) followed by a SID."""
    if off + 4 > len(d):
        return len(d)
    if struct.unpack_from("<I", d, off)[0] == 0:
        return off + 4
    tok = 2 * ptr
    if off + tok + 2 > len(d):
        return len(d)
    return off + tok + 8 + 4 * d[off + tok + 1]


class EtlReader:
    """reader.on(guid, (opcodes), fn) then reader.run(). fn(ts, tid, pid, cpu, ver, opcode, data)."""

    def __init__(self, path):
        self.path = str(path)
        self.handlers = {}
        self.header = {}
        self.total = 0
        self.handled = 0
        self.errors = 0
        self.first_errors = []
        self.progress = None
        self.progress_every = 1_000_000

    def on(self, guid, opcodes, fn):
        for op in opcodes:
            self.handlers[(guid, op)] = fn

    def _cb(self, p):
        try:
            self.total += 1
            if self.progress and self.total % self.progress_every == 0:
                self.progress(self.total)
            flags, tid, pid, ts, guid, ver, op, cpu, udl, ud = HDR.unpack(C.string_at(p, 104))
            h = self.handlers.get((guid, op))
            if h is None:
                return
            self.handled += 1
            h(ts, tid, pid, cpu, ver, op, C.string_at(ud, udl) if udl and ud else b"")
        except Exception as e:  # never let an exception cross the ctypes callback boundary
            self.errors += 1
            if len(self.first_errors) < 8:
                import traceback
                self.first_errors.append("".join(traceback.format_exception(e)))

    def run(self):
        lf = EVENT_TRACE_LOGFILEW()
        lf.LogFileName = self.path
        lf.ProcessTraceMode = MODE_EVENT_RECORD | MODE_RAW_TIMESTAMP
        cb = EVENT_RECORD_CALLBACK(self._cb)  # keep a reference for the whole ProcessTrace call
        lf.EventRecordCallback = cb
        h = _adv.OpenTraceW(C.byref(lf))
        if h == INVALID_HANDLE:
            raise OSError(C.get_last_error(), f"OpenTrace failed for {self.path}")
        hd = lf.LogfileHeader
        self.header = {
            "perf_freq": hd.PerfFreq, "clock_type": hd.ReservedFlags,
            "clock": CLOCK_NAMES.get(hd.ReservedFlags, str(hd.ReservedFlags)),
            "start_filetime": hd.StartTime, "end_filetime": hd.EndTime, "boot_filetime": hd.BootTime,
            "cpus": hd.NumberOfProcessors, "pointer_size": hd.PointerSize, "events_lost": hd.EventsLost,
            "buffers_lost": hd.BuffersLost, "timer_resolution_100ns": hd.TimerResolution,
            "cpu_mhz": hd.CpuSpeedInMHz, "buffers_written": hd.BuffersWritten,
        }
        try:
            arr = (C.c_uint64 * 1)(h)
            rc = _adv.ProcessTrace(arr, 1, None, None)
        finally:
            _adv.CloseTrace(h)
        self.header["process_rc"] = rc
        self.header["events_lost_read"] = lf.EventsLost
        if rc not in (0, 1223):  # 1223 = ERROR_CANCELLED
            raise OSError(rc, f"ProcessTrace failed ({rc}) for {self.path}")
        return self.header
