"""Run an external tool as a bounded process tree: wall-clock limit, memory limit, and on breach the
whole tree is killed (the tool's own children included), not only the direct child.

Why not subprocess.run(timeout=...): it kills the direct child only. OpenGrep starts worker
processes (opengrep-core) that inherit the stdout/stderr pipes; after the timeout, run() waits for
those pipes to close, so the "timeout" returns only when the orphaned workers finish (about 3 hours
on one repository). Here output goes to temporary files instead of pipes, and the tree is killed:

  Windows  the child is put in a Job object (KILL_ON_JOB_CLOSE, optional JOB_MEMORY limit enforced by
           the kernel); TerminateJobObject kills every process in it, orphans included.
  POSIX    the child leads a new session (process group); os.killpg kills the group. Memory is the
           summed RSS of the group (`ps`), sampled every `poll` seconds. The standard library has no
           aggregate limit for a process tree (that needs cgroups), so this limit is *sampled*, not
           enforced: a peak between two samples, or in a run shorter than one sample, is not seen.
           run_tree says so ("memory_limit": "sampled") and the caller reports it as a coverage gap.

Standard library only.
"""
import os
import subprocess
import sys
import tempfile
import time

WINDOWS = sys.platform == "win32"


def total_memory_mb():
    """Physical memory in MiB, or None when it cannot be read."""
    try:
        if WINDOWS:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            st = MEMORYSTATUSEX()
            st.dwLength = ctypes.sizeof(st)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return st.ullTotalPhys // (1024 * 1024)
            return None
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1024 * 1024)
    except (OSError, ValueError, AttributeError):
        return None


def default_memory_mb():
    """Default memory budget for one engine run: half the machine's RAM, at most 8 GiB."""
    total = total_memory_mb()
    return min(8192, total // 2) if total else 4096


class _Job:
    """Windows Job object holding the whole process tree."""

    def __init__(self, max_mb):
        import ctypes
        from ctypes import wintypes
        self.ct = ctypes
        k = self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateJobObjectW.restype = wintypes.HANDLE
        k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        for fn in (k.SetInformationJobObject, k.QueryInformationJobObject):
            fn.restype = wintypes.BOOL
        k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                                ctypes.c_void_p]
        k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k.CloseHandle.argtypes = [wintypes.HANDLE]

        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]

        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class Extended(ctypes.Structure):
            _fields_ = [("Basic", Basic), ("Io", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        self.Extended = Extended
        self.handle = k.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError("CreateJobObject failed")
        info = Extended()
        info.Basic.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if max_mb:
            # JOB_OBJECT_LIMIT_JOB_MEMORY: committed memory of the whole tree. A safety net above the
            # budget: at the budget itself allocations would fail just below it and the poll in
            # run_tree, which kills the tree and reports "memory", would never see the breach.
            info.Basic.LimitFlags |= 0x200
            info.JobMemoryLimit = int(max_mb * 1.25) * 1024 * 1024
        if not k.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise OSError("SetInformationJobObject failed")

    def assign(self, proc):
        return bool(self.k32.AssignProcessToJobObject(self.handle, int(proc._handle)))

    def peak_mb(self):
        info = self.Extended()
        ok = self.k32.QueryInformationJobObject(self.handle, 9, self.ct.byref(info), self.ct.sizeof(info), None)
        return info.PeakJobMemoryUsed // (1024 * 1024) if ok else None

    def kill(self):
        self.k32.TerminateJobObject(self.handle, 1)

    def close(self):
        self.k32.CloseHandle(self.handle)


def _group_rss_mb(pgid):
    """Summed RSS (MiB) of the processes in process group `pgid` (POSIX), or None."""
    try:
        out = subprocess.run(["ps", "-A", "-o", "pgid=,rss="], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    kb = 0
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == str(pgid) and parts[1].isdigit():
            kb += int(parts[1])
    return kb // 1024


def _kill_tree(proc, job, exited):
    if WINDOWS:
        if job:
            job.kill()
        if not exited:
            # a process that escaped the job (assignment raced its first child) is still in the parent
            # tree. Only while the parent lives: after it exited its PID may belong to another program.
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
    else:
        import signal
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        pass


def run_tree(cmd, timeout, max_memory_mb=0, poll=1.0, cwd=None):
    """Run `cmd` and return {"returncode", "stdout", "stderr", "killed": None|"timeout"|"memory"|
    "unmeasured", "seconds", "peak_memory_mb", "memory_limit": None|"enforced"|"sampled"}.
    On timeout or when the tree's memory exceeds `max_memory_mb` (0 = no limit), every process of
    the tree is killed and the call returns at once.
    - "enforced" (Windows Job object): the peak is the exact peak of the whole tree, also checked
      after a run that ended before the first poll.
    - "sampled" (POSIX): breaches seen by a sample are killed; nothing is claimed about the peak
      between samples. No lower bound (e.g. getrusage of one reaped child) is used as proof.
    - No way to measure the tree at all (Windows: no Job object; POSIX: no `ps`): the tree is killed
      ("unmeasured", fails closed), also when the run ended before the first poll. A limit of 0 opts out."""
    t0 = time.time()
    out_f = tempfile.TemporaryFile()
    err_f = tempfile.TemporaryFile()
    job, killed, peak = None, None, None
    try:
        if WINDOWS:
            proc = subprocess.Popen(cmd, stdout=out_f, stderr=err_f, stdin=subprocess.DEVNULL, cwd=cwd,
                                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            try:
                job = _Job(max_memory_mb)
                if not job.assign(proc):
                    job.close()
                    job = None
            except OSError:
                job = None
            measurable = job is not None
        else:
            proc = subprocess.Popen(cmd, stdout=out_f, stderr=err_f, stdin=subprocess.DEVNULL, cwd=cwd,
                                    start_new_session=True)
            measurable = _group_rss_mb(proc.pid) is not None  # `ps` works (a group already gone reads 0)
        while proc.poll() is None:
            elapsed = time.time() - t0
            if elapsed >= timeout:
                killed = "timeout"
                break
            if max_memory_mb and not measurable:
                killed = "unmeasured"  # the limit cannot be enforced on the whole tree: fail closed
                break
            mem = job.peak_mb() if job else (None if WINDOWS else _group_rss_mb(proc.pid))
            if mem is not None:
                peak = max(peak or 0, mem)
                if max_memory_mb and mem >= max_memory_mb:
                    killed = "memory"
                    break
            time.sleep(max(0.05, min(poll, timeout - elapsed)))
        exited = killed is None
        if job:
            peak = max(peak or 0, job.peak_mb() or 0)  # exact peak of the whole tree, from the kernel
        if exited and max_memory_mb:  # a run that ended before (or between) polls is checked as well
            if not measurable:
                killed = "unmeasured"
            elif job and peak >= max_memory_mb:
                killed = "memory"
        mode = None if not max_memory_mb or not measurable else ("enforced" if job else "sampled")
        # also after a normal exit: workers the tool left behind must not outlive the run
        _kill_tree(proc, job, exited=exited)
        out_f.seek(0)
        err_f.seek(0)
        return {"returncode": proc.returncode, "killed": killed, "seconds": round(time.time() - t0, 1),
                "peak_memory_mb": peak, "memory_limit": mode,
                "stdout": out_f.read().decode("utf-8", errors="replace"),
                "stderr": err_f.read().decode("utf-8", errors="replace")}
    finally:
        if job:
            job.close()
        out_f.close()
        err_f.close()
