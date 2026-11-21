// NetGuard launch stub. Windows starts this instead of a gated program (Image File Execution
// Options "Debugger" value, limited to exact paths with UseFilter/FilterFullPath). It asks the
// elevated Gatekeeper over a pipe whether the launch is OK, then starts the real program with
// the same command line, console, std handles and working folder, waits for it and returns
// its exit code. If the Gatekeeper is not running it allows the launch (fail-open), so a
// crash can never lock up your tools.
// Registered as: "C:\ProgramData\NetGuard\ngstub.exe" "--image=<real exe path>"
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;

static class Stub
{
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO
    {
        public int cb; public IntPtr lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS { public ulong a, b, c, d, e, f; }
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION { public JOBOBJECT_BASIC_LIMIT_INFORMATION Basic; public IO_COUNTERS Io; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }

    [DllImport("kernel32.dll")] static extern void GetStartupInfoW(out STARTUPINFO si);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] static extern bool DebugActiveProcessStop(int pid);
    [DllImport("kernel32.dll")] static extern bool DebugSetProcessKillOnExit(bool kill);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr CreateJobObjectW(IntPtr a, string name);
    [DllImport("kernel32.dll")] static extern bool SetInformationJobObject(IntPtr job, int cls, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, int len);
    [DllImport("kernel32.dll")] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
    [DllImport("kernel32.dll")] static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("kernel32.dll")] static extern uint GetConsoleProcessList(uint[] list, uint count);
    [DllImport("kernel32.dll")] static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr h, int flags, StringBuilder name, ref int size);

    // Splits off the first token of a raw Windows command line (quotes respected).
    static string SkipToken(string s, out string token)
    {
        int i = 0; while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
        int start = i; bool q = false;
        while (i < s.Length && (q || !char.IsWhiteSpace(s[i]))) { if (s[i] == '"') q = !q; i++; }
        token = s.Substring(start, i - start).Replace("\"", "");
        while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
        return s.Substring(i);
    }

    static bool Ask(string image, string cmd)
    {
        try
        {
            using (var c = new NamedPipeClientStream(".", "NetGuardGate", PipeDirection.InOut))
            {
                c.Connect(3000);
                // Only trust the answer if it comes from the real Gatekeeper.
                uint spid;
                if (!GetNamedPipeServerProcessId(c.SafePipeHandle.DangerousGetHandle(), out spid)) return true;
                string spath = "";
                IntPtr h = OpenProcess(0x1000, false, (int)spid); // QUERY_LIMITED_INFORMATION works on elevated processes
                if (h != IntPtr.Zero) { var sb = new StringBuilder(1024); int n = sb.Capacity; if (QueryFullProcessImageNameW(h, 0, sb, ref n)) spath = sb.ToString(); CloseHandle(h); }
                if (!spath.Equals(@"C:\ProgramData\NetGuard\gatekeeper.exe", StringComparison.OrdinalIgnoreCase)) return false;
                var w = new StreamWriter(c, new UTF8Encoding(false)) { AutoFlush = true };
                w.WriteLine(image);
                w.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(cmd)));
                string answer = new StreamReader(c, Encoding.UTF8).ReadLine();
                return answer != "BLOCK";
            }
        }
        catch { return true; } // Gatekeeper not running: fail open
    }

    static int Main()
    {
        string rest, me, imageArg;
        rest = SkipToken(Environment.CommandLine, out me);
        rest = SkipToken(rest, out imageArg);
        if (!imageArg.StartsWith("--image=")) { Console.Error.WriteLine("ngstub: missing --image"); return 1; }
        string image = imageArg.Substring(8);
        string cmd = rest.Length > 0 ? rest : "\"" + image + "\"";

        if (!Ask(image, cmd))
        {
            Console.Error.WriteLine("NetGuard blocked " + Path.GetFileName(image) + " (suspicious use). See: netguard gatelog");
            return 1;
        }

        SetConsoleCtrlHandler(IntPtr.Zero, true); // Ctrl+C is for the real program, not us
        STARTUPINFO si; GetStartupInfoW(out si);
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        uint flags = 0x00000002; // DEBUG_ONLY_THIS_PROCESS: lets us start the real exe without re-triggering the IFEO hook
        uint[] plist = new uint[4];
        if (GetConsoleProcessList(plist, 4) == 0) flags |= 0x08000000; // no console here: don't pop a window for the child
        PROCESS_INFORMATION pi;
        if (!CreateProcessW(image, new StringBuilder(cmd, cmd.Length + 1), IntPtr.Zero, IntPtr.Zero, true, flags, IntPtr.Zero, null, ref si, out pi))
        {
            Console.Error.WriteLine("ngstub: could not start " + image + " (error " + Marshal.GetLastWin32Error() + ")");
            return 1;
        }
        DebugSetProcessKillOnExit(false);
        DebugActiveProcessStop(pi.dwProcessId);
        // If this stub is killed (e.g. a tool cancels the "node"/"curl" it started), the real
        // program dies with it. Its own children are not affected (silent breakaway).
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job != IntPtr.Zero)
        {
            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.Basic.LimitFlags = 0x2000 | 0x1000; // KILL_ON_JOB_CLOSE | SILENT_BREAKAWAY_OK
            SetInformationJobObject(job, 9, ref info, Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
            AssignProcessToJobObject(job, pi.hProcess);
        }
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
        uint code; GetExitCodeProcess(pi.hProcess, out code);
        CloseHandle(pi.hProcess);
        return unchecked((int)code);
    }
}
