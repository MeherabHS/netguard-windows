// NetGuard Gatekeeper - watches programs that NetGuard lets onto the internet (curl, python,
// node, git, ssh, PowerShell, browsers, ...). The moment one starts, it is paused and the chain
// of programs that started it is checked. Normal use (you, your terminal, your IDE, signed apps)
// is resumed instantly and silently. Suspicious use - e.g. started by a script runner, by an
// unsigned program in a user folder, a renamed system tool, uploading browser password files,
// sending to a webhook/paste site - stays paused and you get a window with the details and
// the reasons, and decide: Block (default after 60 s) or Allow.
// Runs elevated in your session (task "NetGuard Gatekeeper"), so a normal program cannot
// close it or click its window. Log: C:\ProgramData\NetGuard\gate.log
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

static class Gate
{
    const string Dir = @"C:\ProgramData\NetGuard";
    static readonly string LogPath = Path.Combine(Dir, "gate.log");
    static readonly string TrustPath = Path.Combine(Dir, "gate-trust.txt");
    static bool Debug { get { return File.Exists(Path.Combine(Dir, "gate-debug.flag")); } }
    static readonly object DialogLock = new object(), LogLock = new object(), CacheLock = new object();

    // Gated before start by ngstub.exe (IFEO): curl, ssh, git-remote-https, node, gh, python.
    // Browsers are checked right after they start (WMI), because hooking them would slow every link click.
    static readonly string[] Watched = { "msedge.exe", "opera.exe" };
    static readonly HashSet<string> Browsers = Set("msedge.exe", "opera.exe");
    static readonly HashSet<string> ScriptRunners = Set("wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
        "hh.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe", "wmic.exe");
    static readonly HashSet<string> SystemTools = Set("wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
        "hh.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe", "wmic.exe", "powershell.exe", "cmd.exe",
        "curl.exe", "certutil.exe", "bitsadmin.exe", "csc.exe", "jsc.exe", "vbc.exe", "msiexec.exe", "aspnet_compiler.exe");
    static readonly HashSet<string> DevParents = Set("dart.exe", "node.exe", "code.exe", "python.exe", "java.exe");
    static readonly HashSet<string> StopAt = Set("explorer.exe", "services.exe", "wininit.exe", "winlogon.exe", "userinit.exe");

    static readonly Regex ExfilHost = new Regex(@"discord(app)?\.com/api/webhooks|api\.telegram\.org|pastebin\.com|transfer\.sh|file\.io|ngrok|anonfiles|gofile\.io|webhook\.site|requestbin|pipedream|temp\.sh|bashupload|0x0\.st|paste\.ee|hastebin|catbox\.moe|filebin", RegexOptions.IgnoreCase);
    static readonly Regex RawIp = new Regex(@"https?://\d{1,3}(\.\d{1,3}){3}", RegexOptions.IgnoreCase);
    static readonly Regex Upload = new Regex(@"(^|\s)(-T|--upload-file|-F|--form|--data-binary|-d\s*@|--data(-raw|-urlencode)?\s*@)|Start-BitsTransfer|/upload\b|UploadFile|UploadData", RegexOptions.IgnoreCase);
    static readonly Regex Sensitive = new Regex(@"Login Data|\\Cookies|Local State|Web Data|\\\.ssh\\|id_rsa|id_ed25519|wallet\.dat|Exodus|tdata|ssfn|\.env\b|\\Steam\\config|credentials\.json|\.kdbx", RegexOptions.IgnoreCase);
    static readonly Regex Base64Blob = new Regex(@"[A-Za-z0-9+/]{200,}={0,2}");
    static readonly Regex Encoded = new Regex(@"\s-(e|ec|enc|encodedcommand)\s|FromBase64String", RegexOptions.IgnoreCase);
    static readonly Regex Hidden = new Regex(@"-w(indowstyle)?\s+hid", RegexOptions.IgnoreCase);
    static readonly Regex DebugPort = new Regex(@"--remote-debugging-(port|pipe)|--headless|--dump-dom", RegexOptions.IgnoreCase);

    static HashSet<string> Set(params string[] a) { return new HashSet<string>(a, StringComparer.OrdinalIgnoreCase); }

    // ---------------- native ----------------
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtResumeProcess(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool SetProcessWorkingSetSize(IntPtr h, IntPtr min, IntPtr max);
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)] static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, IntPtr data);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WtFile { public uint cb; public string path; public IntPtr hFile; public IntPtr known; }
    [StructLayout(LayoutKind.Sequential)]
    struct WtData { public uint cb; public IntPtr policy, sip; public uint ui, revoke, choice; public IntPtr file; public uint state; public IntPtr hState, url; public uint prov, ctx; public IntPtr settings; }

    static bool Suspend(int pid, bool on)
    {
        IntPtr h = OpenProcess(0x0800, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return (on ? NtSuspendProcess(h) : NtResumeProcess(h)) == 0; } finally { CloseHandle(h); }
    }

    static void Trim() { GC.Collect(); SetProcessWorkingSetSize(Process.GetCurrentProcess().Handle, (IntPtr)(-1), (IntPtr)(-1)); }

    // ---------------- signatures / location ----------------
    static readonly Dictionary<string, string> SigCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    // "" = no valid embedded signature, otherwise the signer's name.
    static string Signer(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return "";
        string key = path + "|" + File.GetLastWriteTimeUtc(path).Ticks;
        lock (CacheLock) { string c; if (SigCache.TryGetValue(key, out c)) return c; }
        string result = "";
        IntPtr pf = IntPtr.Zero, pd = IntPtr.Zero;
        try
        {
            var f = new WtFile { cb = (uint)Marshal.SizeOf(typeof(WtFile)), path = path };
            pf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WtFile))); Marshal.StructureToPtr(f, pf, false);
            var d = new WtData { cb = (uint)Marshal.SizeOf(typeof(WtData)), ui = 2, revoke = 0, choice = 1, file = pf, prov = 0x10 | 0x1000 };
            pd = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WtData))); Marshal.StructureToPtr(d, pd, false);
            Guid g = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            if (WinVerifyTrust(IntPtr.Zero, ref g, pd) == 0)
            {
                var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
                result = cert.GetNameInfo(X509NameType.SimpleName, false);
                if (string.IsNullOrEmpty(result)) result = "valid signature";
            }
        }
        catch { result = ""; }
        finally { if (pf != IntPtr.Zero) Marshal.FreeHGlobal(pf); if (pd != IntPtr.Zero) Marshal.FreeHGlobal(pd); }
        lock (CacheLock) { if (SigCache.Count > 500) SigCache.Clear(); SigCache[key] = result; }
        return result;
    }

    static readonly string Win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
    static readonly string[] Protected = { Win, @"C:\Program Files\", @"C:\Program Files (x86)\" };
    static readonly string[] WinWritable = { Win + @"Temp\", Win + @"Tasks\", Win + @"tracing\", Win + @"System32\Tasks\", Win + @"System32\spool\", Win + @"SysWOW64\Tasks\" };

    // Folders only administrators can write to.
    static bool InProtectedFolder(string p)
    {
        if (string.IsNullOrEmpty(p)) return false;
        if (WinWritable.Any(w => p.StartsWith(w, StringComparison.OrdinalIgnoreCase))) return false;
        return Protected.Any(w => p.StartsWith(w, StringComparison.OrdinalIgnoreCase));
    }

    static List<string> TrustList()
    {
        try { return File.ReadAllLines(TrustPath).Select(l => l.Trim()).Where(l => l.Length > 3 && !l.StartsWith("#")).ToList(); }
        catch { return new List<string>(); }
    }

    // ---------------- process info ----------------
    class PInfo { public int Pid, Ppid; public string Name = "", Path = "", Cmd = ""; public DateTime Created; public string Sig = ""; }

    static PInfo Query(int pid)
    {
        if (pid <= 4) return null;
        try
        {
            using (var s = new ManagementObjectSearcher("SELECT ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate FROM Win32_Process WHERE ProcessId=" + pid))
            using (var r = s.Get())
                foreach (ManagementObject o in r)
                {
                    var p = new PInfo
                    {
                        Pid = pid,
                        Ppid = Convert.ToInt32(o["ParentProcessId"]),
                        Name = (o["Name"] as string) ?? "",
                        Path = (o["ExecutablePath"] as string) ?? "",
                        Cmd = (o["CommandLine"] as string) ?? "",
                    };
                    string cd = o["CreationDate"] as string;
                    p.Created = cd != null ? ManagementDateTimeConverter.ToDateTime(cd) : DateTime.MinValue;
                    o.Dispose();
                    return p;
                }
        }
        catch { }
        return null;
    }

    // Fast path: one process snapshot + one WMI query for all command lines (was one WMI query per parent).
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct PE32 { public uint dwSize, cntUsage, th32ProcessID; public IntPtr th32DefaultHeapID; public uint th32ModuleID, cntThreads, th32ParentProcessID; public int pcPriClassBase; public uint dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile; }
    [DllImport("kernel32.dll")] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32FirstW(IntPtr snap, ref PE32 pe);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32NextW(IntPtr snap, ref PE32 pe);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr h, int flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr h, out long create, out long exit, out long kernel, out long user);

    static Dictionary<int, KeyValuePair<int, string>> Snapshot()
    {
        var d = new Dictionary<int, KeyValuePair<int, string>>();
        IntPtr snap = CreateToolhelp32Snapshot(2, 0);
        if (snap == IntPtr.Zero || snap == (IntPtr)(-1)) return d;
        try
        {
            var pe = new PE32 { dwSize = (uint)Marshal.SizeOf(typeof(PE32)) };
            if (Process32FirstW(snap, ref pe))
                do { d[(int)pe.th32ProcessID] = new KeyValuePair<int, string>((int)pe.th32ParentProcessID, pe.szExeFile ?? ""); } while (Process32NextW(snap, ref pe));
        }
        finally { CloseHandle(snap); }
        return d;
    }

    static PInfo Native(int pid, Dictionary<int, KeyValuePair<int, string>> snap)
    {
        KeyValuePair<int, string> e;
        if (pid <= 4 || !snap.TryGetValue(pid, out e)) return null;
        var p = new PInfo { Pid = pid, Ppid = e.Key, Name = e.Value, Created = DateTime.MinValue };
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h != IntPtr.Zero)
        {
            try
            {
                var sb = new StringBuilder(1024); int n = sb.Capacity;
                if (QueryFullProcessImageNameW(h, 0, sb, ref n)) p.Path = sb.ToString();
                long c, x, k, u; if (GetProcessTimes(h, out c, out x, out k, out u)) p.Created = DateTime.FromFileTimeUtc(c);
            }
            finally { CloseHandle(h); }
        }
        return p;
    }

    static void FillCommandLines(IEnumerable<PInfo> ps)
    {
        var need = ps.Where(p => p.Cmd.Length == 0).ToList();
        if (need.Count == 0) return;
        try
        {
            string where = string.Join(" OR ", need.Select(p => "ProcessId=" + p.Pid));
            using (var s = new ManagementObjectSearcher("SELECT ProcessId,CommandLine FROM Win32_Process WHERE " + where))
            using (var r = s.Get())
                foreach (ManagementObject o in r)
                {
                    int id = Convert.ToInt32(o["ProcessId"]);
                    foreach (var p in need.Where(q => q.Pid == id)) p.Cmd = (o["CommandLine"] as string) ?? "";
                    o.Dispose();
                }
        }
        catch { }
    }

    static string OriginalName(string path)
    {
        try { var o = FileVersionInfo.GetVersionInfo(path).OriginalFilename; return o == null ? "" : Regex.Replace(o.Trim(), @"\.mui$", "", RegexOptions.IgnoreCase); }
        catch { return ""; }
    }

    // ---------------- evaluation ----------------
    class Verdict
    {
        public PInfo Target; public List<PInfo> Chain = new List<PInfo>();
        public List<string> Strong = new List<string>(), Medium = new List<string>();
        public PInfo FirstUntrusted;
        public bool Prompt { get { return Strong.Count > 0 || FirstUntrusted != null || Medium.Count >= 2; } }
    }

    static Verdict Evaluate(int pid) { var snap = Snapshot(); return Evaluate(Native(pid, snap), snap); }

    static Verdict Evaluate(PInfo target, Dictionary<int, KeyValuePair<int, string>> snap)
    {
        var v = new Verdict();
        v.Target = target;
        if (v.Target == null) return v;
        var trust = TrustList();
        Func<string, bool> trusted = p => trust.Any(t => p.StartsWith(t, StringComparison.OrdinalIgnoreCase));

        // Walk up the parents (stop at explorer / services / Task Scheduler).
        PInfo cur = v.Target;
        for (int i = 0; i < 8; i++)
        {
            PInfo par = Native(cur.Ppid, snap);
            if (par == null || (par.Created > cur.Created && cur.Created != DateTime.MinValue && par.Created != DateTime.MinValue))
            {
                v.Medium.Add("The program that started it has already closed (launchers that hide themselves do this).");
                break;
            }
            v.Chain.Add(par);
            if (par.Name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase) || StopAt.Contains(par.Name)) break;
            cur = par;
        }
        FillCommandLines(new[] { v.Target }.Concat(v.Chain));
        var last = v.Chain.LastOrDefault();
        if (last != null && last.Name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
            v.Medium.Add(last.Cmd.IndexOf("Schedule", StringComparison.OrdinalIgnoreCase) >= 0
                ? "It was started in the background by a scheduled task, not by you."
                : "It was started in the background by a Windows service, not by you.");

        bool browser = Browsers.Contains(v.Target.Name);
        var everyone = new List<PInfo> { v.Target }; everyone.AddRange(v.Chain);
        foreach (var p in everyone)
        {
            bool isTarget = p == v.Target;
            string orig = OriginalName(p.Path);
            string fileName = Path.GetFileName(p.Path);
            if (!browser && !isTarget && ScriptRunners.Contains(p.Name) &&
                !(p.Name.Equals("msbuild.exe", StringComparison.OrdinalIgnoreCase) && p.Path.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase)))
                v.Strong.Add(string.Format("It was started through {0}, a Windows script runner that malware commonly uses (a standard infostealer technique).", p.Name));
            if (orig.Length > 0 && SystemTools.Contains(orig) && fileName.Length > 0 && !orig.Equals(fileName, StringComparison.OrdinalIgnoreCase))
                v.Strong.Add(string.Format("{0} is really the Windows tool {1} under a different name. Renaming system tools is a malware trick (infostealers do this with MSBuild.exe).", fileName, orig));
            else if (orig.Length > 0 && SystemTools.Contains(orig) && p.Path.Length > 0 && !InProtectedFolder(p.Path))
                v.Strong.Add(string.Format("A copy of the Windows tool {0} is running from {1} instead of the Windows folder.", orig, Path.GetDirectoryName(p.Path)));

            if (p.Path.StartsWith(Dir + "\\", StringComparison.OrdinalIgnoreCase)) { p.Sig = "NetGuard"; continue; }
            if (p.Path.Length > 0 && !InProtectedFolder(p.Path) && !trusted(p.Path))
            {
                p.Sig = Signer(p.Path);
                if (p.Sig.Length == 0 && v.FirstUntrusted == null)
                {
                    v.FirstUntrusted = p;
                    v.Medium.Add(string.Format("{0} ({1}) is not digitally signed and sits in a folder any program can write to - this is where downloaded and malicious programs live.",
                        isTarget ? "This copy of " + p.Name : "The program that started it, " + p.Name, p.Path));
                }
            }
            else if (p.Path.Length > 0) p.Sig = InProtectedFolder(p.Path) ? "protected folder" : "your trust list";

            string c = p.Cmd;
            if (c.Length == 0) continue;
            if (ExfilHost.IsMatch(c)) v.Strong.Add("It sends to " + ExfilHost.Match(c).Value + ", a webhook / paste / file-drop service that stolen data is commonly sent to.");
            if (Upload.IsMatch(c) && Sensitive.IsMatch(c)) v.Strong.Add("It uploads a sensitive file (" + Sensitive.Match(c).Value + ") - passwords, browser logins, keys or secrets.");
            else
            {
                if (Upload.IsMatch(c)) v.Medium.Add("It uploads data (" + Upload.Match(c).Value.Trim() + ").");
                if (Sensitive.IsMatch(c)) v.Medium.Add("Its command mentions a sensitive file (" + Sensitive.Match(c).Value + ").");
            }
            bool isPs = p.Name.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) || p.Name.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase);
            if ((isPs && Encoded.IsMatch(c)) || c.IndexOf("FromBase64String", StringComparison.OrdinalIgnoreCase) >= 0) v.Strong.Add("It runs a hidden, encoded (base64) command so you can't read what it does.");
            else if (Base64Blob.IsMatch(c)) v.Medium.Add("Its command contains a long encoded blob.");
            if (RawIp.IsMatch(c)) v.Medium.Add("It connects to a bare IP address (" + RawIp.Match(c).Value + ") instead of a named website.");
            if (Hidden.IsMatch(c)) v.Medium.Add("It asks to run with its window hidden.");
            if (browser && isTarget && DebugPort.IsMatch(c))
            {
                PInfo par = v.Chain.Count > 0 ? v.Chain[0] : null;
                if (par == null || !DevParents.Contains(par.Name))
                    v.Strong.Add("The browser is being opened in remote-control mode (" + DebugPort.Match(c).Value + "). Cookie stealers use this to copy your logged-in sessions.");
            }
        }
        // De-duplicate.
        v.Strong = v.Strong.Where(s => s.Length > 0).Distinct().ToList();
        v.Medium = v.Medium.Distinct().ToList();
        return v;
    }

    // ---------------- dialog ----------------
    enum Choice { Block, BlockParent, AllowOnce, AllowTrust }

    static string Describe(PInfo p)
    {
        return string.Format("{0}   [{1}]\r\n      {2}", p.Name, p.Sig.Length > 0 ? p.Sig : "NOT signed", p.Path.Length > 0 ? p.Path : "(path unknown)");
    }

    static string Clip(string s, int n) { s = s ?? ""; return s.Length <= n ? s : s.Substring(0, n) + " ..."; }

    static Choice Ask(Verdict v)
    {
        Choice choice = Choice.Block;
        int seconds = v.Target.Cmd.Contains("NETGUARD-SELFTEST") ? 8 : 60;
        var sb = new StringBuilder();
        sb.AppendLine("PROGRAM THAT WANTS THE INTERNET");
        sb.AppendLine("  " + Describe(v.Target).Replace("\r\n", "\r\n  "));
        sb.AppendLine();
        sb.AppendLine("WHAT IT WAS TOLD TO DO");
        sb.AppendLine("  " + Clip(v.Target.Cmd, 900));
        sb.AppendLine();
        sb.AppendLine("STARTED BY (closest first)");
        int i = 0;
        foreach (var p in v.Chain) { i++; sb.AppendLine(string.Format("  {0}. {1}", i, Describe(p).Replace("\r\n", "\r\n  "))); sb.AppendLine("      command: " + Clip(p.Cmd, 300)); }
        if (i == 0) sb.AppendLine("  (unknown - the starter has already closed)");
        sb.AppendLine();
        sb.AppendLine("WHY THIS LOOKS SUSPICIOUS");
        foreach (var s in v.Strong) sb.AppendLine("  !! " + s);
        foreach (var s in v.Medium) sb.AppendLine("  -  " + s);
        sb.AppendLine();
        sb.AppendLine("RECOMMENDATION");
        sb.AppendLine("  Block it, unless you started this yourself just now and recognise every program listed above.");
        sb.AppendLine("  The program is on hold and has not sent anything.");

        var t = new Thread(() =>
        {
            using (var f = new Form())
            {
                f.Text = "NetGuard - suspicious internet attempt on hold";
                f.Font = new Font("Segoe UI", 10f);
                f.StartPosition = FormStartPosition.CenterScreen;
                f.TopMost = true; f.ShowInTaskbar = true; f.MinimizeBox = false; f.MaximizeBox = false;
                f.FormBorderStyle = FormBorderStyle.FixedDialog;
                f.ClientSize = new Size(820, 600);
                var head = new Label { Text = string.Format("{0} was put on hold before it could use the internet.", v.Target.Name), Font = new Font("Segoe UI", 12f, FontStyle.Bold), ForeColor = Color.FromArgb(176, 32, 32), AutoSize = false, Bounds = new Rectangle(16, 12, 790, 28) };
                var box = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 9.5f), Text = sb.ToString(), Bounds = new Rectangle(16, 46, 788, 470), BackColor = Color.White };
                var bBlock = new Button { Text = "Block", Bounds = new Rectangle(16, 528, 150, 56) };
                var bBlockParent = new Button { Text = "Block and close\r\nwhat started it", Bounds = new Rectangle(176, 528, 170, 56), Enabled = v.FirstUntrusted != null && v.FirstUntrusted != v.Target };
                var bOnce = new Button { Text = "Allow once", Bounds = new Rectangle(476, 528, 150, 56) };
                var bTrust = new Button { Text = "Allow and always\r\ntrust " + (v.FirstUntrusted != null ? Clip(v.FirstUntrusted.Name, 18) : "starter"), Bounds = new Rectangle(636, 528, 170, 56), Enabled = v.FirstUntrusted != null && v.Strong.Count == 0 };
                bBlock.Click += (s, e) => { choice = Choice.Block; f.Close(); };
                bBlockParent.Click += (s, e) => { choice = Choice.BlockParent; f.Close(); };
                bOnce.Click += (s, e) => { choice = Choice.AllowOnce; f.Close(); };
                bTrust.Click += (s, e) => { choice = Choice.AllowTrust; f.Close(); };
                var timer = new System.Windows.Forms.Timer { Interval = 1000 };
                int left = seconds;
                bBlock.Text = string.Format("Block ({0})", left);
                timer.Tick += (s, e) => { left--; bBlock.Text = string.Format("Block ({0})", left); if (left <= 0) { choice = Choice.Block; f.Close(); } };
                f.Controls.AddRange(new Control[] { head, box, bBlock, bBlockParent, bOnce, bTrust });
                f.AcceptButton = bBlock; f.CancelButton = bBlock;
                f.Shown += (s, e) => { bBlock.Focus(); f.Activate(); timer.Start(); System.Media.SystemSounds.Exclamation.Play(); };
                f.FormClosed += (s, e) => timer.Stop();
                Application.Run(f);
                timer.Dispose();
            }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.IsBackground = true;
        t.Start(); t.Join();
        return choice;
    }

    // ---------------- main loop ----------------
    static void Log(string m)
    {
        lock (LogLock)
        {
            try
            {
                if (File.Exists(LogPath) && new FileInfo(LogPath).Length > 2 * 1024 * 1024) File.Delete(LogPath);
                File.AppendAllText(LogPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss ") + m + Environment.NewLine);
            }
            catch { }
        }
    }

    static void Kill(int pid) { try { Process.GetProcessById(pid).Kill(); } catch { } }

    // Called on the event thread: pause first, check on a worker thread.
    static void OnStart(int pid, int ppid, string name)
    {
        // Browsers start many child processes of themselves; only check the top one.
        if (Browsers.Contains(name)) { try { if (Process.GetProcessById(ppid).ProcessName.Equals(Path.GetFileNameWithoutExtension(name), StringComparison.OrdinalIgnoreCase)) return; } catch { } }
        bool paused = Suspend(pid, true);
        if (Debug) Log(string.Format("debug: start {0} pid {1} paused={2}", name, pid, paused));
        ThreadPool.QueueUserWorkItem(_ => Handle(pid, paused));
    }

    static void Handle(int pid, bool paused)
    {
        bool resume = true;
        try
        {
            var sw = Stopwatch.StartNew();
            var v = Evaluate(pid);
            if (Debug) Log(string.Format("debug: pid {0} {1} checked in {2} ms, prompt={3}, strong={4}, medium={5}, chain={6}", pid,
                v.Target == null ? "(already exited)" : v.Target.Name, sw.ElapsedMilliseconds, v.Prompt, v.Strong.Count, v.Medium.Count,
                string.Join("<-", v.Chain.Select(c => c.Name))));
            if (v.Target == null || v.Target.Cmd.IndexOf(@"\ProgramData\NetGuard\", StringComparison.OrdinalIgnoreCase) >= 0) return;
            if (!v.Prompt) return;
            string reasons = string.Join(" | ", v.Strong.Concat(v.Medium));
            string chain = string.Join(" <- ", new[] { v.Target.Path }.Concat(v.Chain.Select(c => c.Path.Length > 0 ? c.Path : c.Name)));
            Choice ch;
            lock (DialogLock) { ch = Ask(v); }
            switch (ch)
            {
                case Choice.AllowOnce: Log("ALLOWED ONCE  " + chain + "  cmd: " + Clip(v.Target.Cmd, 400) + "  why-flagged: " + reasons); break;
                case Choice.AllowTrust:
                    try { File.AppendAllText(TrustPath, v.FirstUntrusted.Path + Environment.NewLine); } catch { }
                    Log("ALLOWED+TRUSTED " + v.FirstUntrusted.Path + "  chain: " + chain); break;
                case Choice.BlockParent:
                    resume = false; Kill(pid); if (v.FirstUntrusted != null) Kill(v.FirstUntrusted.Pid);
                    Log("BLOCKED+CLOSED STARTER " + chain + "  cmd: " + Clip(v.Target.Cmd, 400) + "  why: " + reasons); break;
                default:
                    resume = false; Kill(pid);
                    Log("BLOCKED       " + chain + "  cmd: " + Clip(v.Target.Cmd, 400) + "  why: " + reasons); break;
            }
        }
        catch (Exception e) { Log("error checking pid " + pid + ": " + e.Message); }
        finally
        {
            if (resume && paused) Suspend(pid, false);
            Trim();
        }
    }

    // ---------------- pipe: answers ngstub.exe before a gated program starts ----------------
    [DllImport("kernel32.dll")] static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);

    static void PipeLoop()
    {
        var ps = new PipeSecurity();
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        while (true)
        {
            NamedPipeServerStream srv = null;
            try
            {
                srv = new NamedPipeServerStream("NetGuardGate", PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, PipeOptions.None, 8192, 8192, ps);
                srv.WaitForConnection();
                var conn = srv; srv = null;
                ThreadPool.QueueUserWorkItem(_ => Serve(conn));
            }
            catch (Exception e) { Log("pipe error: " + e.Message); if (srv != null) srv.Dispose(); Thread.Sleep(1000); }
        }
    }

    static void Serve(NamedPipeServerStream c)
    {
        using (c)
        {
            try
            {
                uint cpid; GetNamedPipeClientProcessId(c.SafePipeHandle.DangerousGetHandle(), out cpid);
                var r = new StreamReader(c, Encoding.UTF8);
                string image = r.ReadLine() ?? "";
                string cmd = Encoding.UTF8.GetString(Convert.FromBase64String(r.ReadLine() ?? ""));
                bool allow = Decide((int)cpid, image, cmd);
                var w = new StreamWriter(c, new UTF8Encoding(false)) { AutoFlush = true };
                w.WriteLine(allow ? "ALLOW" : "BLOCK");
                c.WaitForPipeDrain();
            }
            catch (Exception e) { Log("pipe client error: " + e.Message); }
        }
        Trim();
    }

    static bool Decide(int stubPid, string image, string cmd)
    {
        var sw = Stopwatch.StartNew();
        var snap = Snapshot();
        PInfo stub = Native(stubPid, snap);
        if (stub == null) return true;
        var t = new PInfo { Pid = stubPid, Ppid = stub.Ppid, Created = stub.Created, Name = Path.GetFileName(image), Path = image, Cmd = cmd.Length > 0 ? cmd : image };
        var v = Evaluate(t, snap);
        if (Debug) Log(string.Format("debug: gate {0} checked in {1} ms, prompt={2}, chain={3}", t.Name, sw.ElapsedMilliseconds, v.Prompt, string.Join("<-", v.Chain.Select(x => x.Name))));
        if (!v.Prompt) return true;
        string reasons = string.Join(" | ", v.Strong.Concat(v.Medium));
        string chain = string.Join(" <- ", new[] { image }.Concat(v.Chain.Select(x => x.Path.Length > 0 ? x.Path : x.Name)));
        Choice ch;
        lock (DialogLock) { ch = Ask(v); }
        switch (ch)
        {
            case Choice.AllowOnce: Log("ALLOWED ONCE  " + chain + "  cmd: " + Clip(cmd, 400) + "  why-flagged: " + reasons); return true;
            case Choice.AllowTrust:
                try { File.AppendAllText(TrustPath, v.FirstUntrusted.Path + Environment.NewLine); } catch { }
                Log("ALLOWED+TRUSTED " + v.FirstUntrusted.Path + "  chain: " + chain); return true;
            case Choice.BlockParent:
                if (v.FirstUntrusted != null) Kill(v.FirstUntrusted.Pid);
                Log("BLOCKED+CLOSED STARTER " + chain + "  cmd: " + Clip(cmd, 400) + "  why: " + reasons); return false;
            default:
                Log("BLOCKED       " + chain + "  cmd: " + Clip(cmd, 400) + "  why: " + reasons); return false;
        }
    }

    [STAThread]
    static void Main()
    {
        bool fresh;
        using (var mutex = new Mutex(true, @"Global\NetGuardGatekeeper", out fresh))
        {
            if (!fresh) return;
            if (!File.Exists(TrustPath))
            {
                string u = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                File.WriteAllLines(TrustPath, new[] {
                    "# NetGuard Gatekeeper trust list: folders whose UNSIGNED programs you trust (one per line).",
                    "# Signed programs and anything in C:\\Windows / C:\\Program Files are trusted already.",
                    u + @"\.cargo\bin\", u + @"\.rustup\toolchains\", u + @"\tools\flutter\", u + @"\AppData\Local\Python\",
                });
            }
            var watchedSet = Set(Watched);
            EventArrivedEventHandler onEvent = (s, e) =>
            {
                try
                {
                    var ev = e.NewEvent;
                    int pid = Convert.ToInt32(ev["ProcessID"]), ppid = Convert.ToInt32(ev["ParentProcessID"]);
                    string name = (string)ev["ProcessName"];
                    ev.Dispose();
                    if (watchedSet.Contains(name)) OnStart(pid, ppid, name);
                }
                catch { }
            };
            ManagementEventWatcher watcher = null;
            string[] queries = {
                "SELECT * FROM Win32_ProcessStartTrace WHERE " + string.Join(" OR ", Watched.Select(w => "ProcessName='" + w + "'")),
                "SELECT * FROM Win32_ProcessStartTrace",
            };
            foreach (var q in queries)
            {
                try
                {
                    watcher = new ManagementEventWatcher(new WqlEventQuery(q));
                    watcher.EventArrived += onEvent;
                    watcher.Start();
                    Log("watching with: " + (q.Contains("WHERE") ? "filtered query" : "unfiltered query"));
                    break;
                }
                catch (Exception ex) { Log("query failed (" + ex.Message.Trim() + "), trying next"); watcher = null; }
            }
            if (watcher == null) { Log("could not watch program starts - exiting so the task restarts me"); Environment.Exit(1); }
            new Thread(PipeLoop) { IsBackground = true }.Start();
            Log("gatekeeper started, watching: " + string.Join(", ", Watched));
            Trim();
            new ManualResetEvent(false).WaitOne();
        }
    }
}
