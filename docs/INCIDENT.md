# The incident that started NetGuard

In November 2026 I found an infostealer on my own Windows 11 PC. It had been running for about five
months without a single antivirus alert. This is how it worked, how I found it, and what it taught me.
The indicators at the end may help someone else check their machine.

## How it got in

The most likely way in was **fake game-repack sites**:

- In June the Windows `hosts` file was edited to redirect about 60 lookalike domains of a popular
  game-repack site to a single server. Anyone typing the real-looking name landed on the attacker's
  copy, which served the "game".
- Over the following weeks, two **root certificates** were added to the Windows certificate store,
  both issued to the same unknown machine name. A planted root certificate lets an attacker's
  servers pass as legitimate HTTPS sites.

## How it ran

The kit was three files, copied into eight folders chosen to look like ordinary vendor or Windows caches:

| File | Role |
|---|---|
| A renamed copy of Microsoft's **`MSBuild.exe`** | A genuine, Microsoft-signed build tool. MSBuild can compile and run code from a project file, so the signature lends trust to whatever it runs. |
| A ~25 MB **`Resources.resx`** | The encrypted payload that MSBuild built and ran. |
| A **`.wsf`** (Windows Script File, JScript) | The launcher, run hidden. |

**Scheduled tasks** started the launcher at every logon. The processes protected themselves with
restrictive access permissions, so they couldn't be stopped without elevation.

Exfiltration went over HTTPS to an address behind Cloudflare, so it looked like normal web traffic.

## How I found it (no antivirus scan)

1. **Unusual parent chains:** a scheduled task starting `wscript` with a `.wsf` file from inside a
   cache folder.
2. **A Microsoft-signed binary in the wrong place:** its `OriginalFilename` said `MSBuild.exe`, but it
   was sitting under a vendor-named folder in `AppData` with a different name.
3. **The same three files repeated** across folders, with matching sizes and dates.
4. **Persistence and tampering:** scheduled tasks pointing at those folders, a `hosts` file far
   larger than normal, and root certificates nobody had installed on purpose.

Removal: an elevated script stopped the processes, deleted the tasks and all eight copies, restored
the `hosts` file and removed the planted root certificates. A second pass over every drive found no
other copies.

## What it taught me

- **A valid signature isn't enough.** The malware ran inside a genuine Microsoft-signed program.
  What matters is *where* a program runs from, *under what name*, and *who started it*.
- **Stealing is only half the job.** An infostealer is useless if it can't send data out. Blocking
  outbound traffic by default would have stopped this one cold, because its renamed MSBuild had no
  allow rule.
- **The next one may borrow a trusted tool.** Instead of its own process, malware can make `curl`,
  `node` or `ssh` do the sending. That's why NetGuard checks who launched those tools.
- **Assume everything on the machine is gone.** Browser-saved passwords, session cookies, tokens and
  keys on an infected machine have to be treated as stolen and rotated, from a clean device.

NetGuard's warning rules map directly to this kit: script runners (`wscript`, `cscript`, `mshta`),
renamed or relocated Windows tools (`MSBuild.exe`), and scheduled-task launches.

## Indicators

| Type | Value |
|---|---|
| Technique | Renamed `MSBuild.exe` + encrypted `Resources.resx` + JScript `.wsf` launcher (MITRE ATT&CK T1127.001, T1036.003, T1053.005) |
| Scheduled task names | `CacheEngine`, `CacheService` |
| Folders used | `%LOCALAPPDATA%\Marvell\Network Helper`, `%LOCALAPPDATA%\TP-Link\WiFi Configuration Utility`, `%LOCALAPPDATA%\Microsoft\Windows\Caches\…`, `…\INetCache\…`, `…\WebCache\…`, `%APPDATA%\Microsoft\Crypto\TimesheetService` |
| Exfiltration | `104.21.40.183:443`, a **shared Cloudflare edge address**. Useful together with the other indicators, but not as a block on its own. |
| Hosts-file redirect target | `109.94.209.70` (about 60 lookalike repack-site domains) |
| Planted root certificates | Subject `CN=DESKTOP-8MRM68O` |
| Active | June 2026 to 22 November 2026 |
