<#
.SYNOPSIS
    Runs a program as a new, throwaway standard (non-admin) local user.

.DESCRIPTION
    Creates a local account with a random name and password, keeps it out of the
    Administrators group, hides it from the sign-in screen, and starts the program
    under it. Once the program, and every other process running as that account,
    has exited, the script deletes the account, its profile and its staging folder.
    Ctrl+C stops those processes and cleans up the same way.

    Creating accounts needs admin rights: run from a normal PowerShell and the
    script asks for them through UAC, then continues in a new elevated window.
    The program itself runs without admin rights.

.PARAMETER Path
    Program to run. If you leave it out, the script asks for it.

.PARAMETER ArgumentList
    Arguments for the program.

.PARAMETER Stage
    Whether to copy the program somewhere the throwaway account can read it:
      None   - run it where it is. Fine for Program Files, System32 and the like.
      File   - copy only the executable.
      Folder - copy the executable's whole folder (for programs with DLLs or data files).
    Programs inside your own profile (Downloads, Desktop, ...) need File or Folder,
    because other accounts cannot read your profile.

.PARAMETER WorkingDirectory
    Working directory for the program. Defaults to the folder of the (staged) program.

.EXAMPLE
    .\usandbox.ps1 C:\Windows\System32\notepad.exe

.EXAMPLE
    .\usandbox.ps1 $HOME\Downloads\tool\tool.exe -Stage Folder -ArgumentList '--verbose', 'input.txt'
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $Path,

    [Parameter(Position = 1)]
    [string[]] $ArgumentList,

    [ValidateSet('None', 'File', 'Folder')]
    [string] $Stage = 'None',

    [string] $WorkingDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-RandomPassword {
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#%+-=?@_~'
    $all = -join $sets
    $bytes = [byte[]]::new(32)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    # The first characters come one from each set, so complexity rules are always met.
    $chars = for ($i = 0; $i -lt $bytes.Length; $i++) {
        $set = if ($i -lt $sets.Count) { $sets[$i] } else { $all }
        $set[$bytes[$i] % $set.Length]
    }
    -join $chars
}

# Start-Process -Credential passes our own environment block to the new process, so
# USERPROFILE, APPDATA, TEMP and friends would point into the calling user's profile,
# which the throwaway account cannot read. Calling CreateProcessWithLogonW with no
# environment block makes Windows build one from the throwaway user's own profile.
if (-not ('USandbox.SandboxProcess' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace USandbox {
    public sealed class SandboxProcess : IDisposable {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO {
            public int cb;
            public string lpReserved, lpDesktop, lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION {
            public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateProcessWithLogonW(string username, string domain, IntPtr password, int logonFlags,
            string applicationName, StringBuilder commandLine, int creationFlags, IntPtr environment,
            string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int WaitForSingleObject(IntPtr handle, int milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeProcess(IntPtr process, out int exitCode);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);

        const int LOGON_WITH_PROFILE = 0x1;
        const int CREATE_NEW_CONSOLE = 0x10;
        const int CREATE_UNICODE_ENVIRONMENT = 0x400;

        IntPtr handle;
        public int Id { get; private set; }

        SandboxProcess(IntPtr handle, int id) { this.handle = handle; Id = id; }

        public static SandboxProcess Start(string user, string domain, SecureString password,
                                           string program, string commandLine, string directory) {
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            PROCESS_INFORMATION pi;
            IntPtr pw = Marshal.SecureStringToGlobalAllocUnicode(password);
            try {
                // A null environment means "build it from the user's profile".
                if (!CreateProcessWithLogonW(user, domain, pw, LOGON_WITH_PROFILE, program,
                        new StringBuilder(commandLine), CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                        IntPtr.Zero, directory, ref si, out pi)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            } finally {
                Marshal.ZeroFreeGlobalAllocUnicode(pw);
            }
            CloseHandle(pi.hThread);
            return new SandboxProcess(pi.hProcess, pi.dwProcessId);
        }

        public bool HasExited { get { return WaitForSingleObject(handle, 0) == 0; } }

        public int ExitCode {
            get {
                int code;
                if (!GetExitCodeProcess(handle, out code)) throw new Win32Exception(Marshal.GetLastWin32Error());
                return code;
            }
        }

        public void Dispose() {
            if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; }
        }
    }
}
'@
}

function Get-SandboxProcess {
    Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
        Where-Object { $_.UserName -eq $qualifiedName }
}

# Runs one cleanup step; a failure is reported but does not stop the remaining steps.
function Invoke-CleanupStep([string] $What, [scriptblock] $Action) {
    try { & $Action } catch { Write-Warning "Could not $What`: $($_.Exception.Message)" }
}

# Quotes a string as a PowerShell single-quoted literal (curly quotes count as quotes too).
function ConvertTo-PSLiteral([string] $Value) {
    "'" + ($Value -replace "['‘’‚‛]", '$0$0') + "'"
}

while (-not $Path) {
    # Drag-and-drop and "Copy as path" wrap the path in quotes.
    $answer = "$(Read-Host 'Path of the program to run')".Trim().Trim('"', "'")
    if (-not $answer) { continue }
    if (Test-Path -LiteralPath $answer -PathType Leaf) { $Path = $answer } else { Write-Warning "Not a file: $answer" }
}

$program = (Resolve-Path -LiteralPath $Path).ProviderPath
if (-not (Test-Path -LiteralPath $program -PathType Leaf)) {
    throw "Not a file: $program"
}
# The elevated copy starts in another folder, so pass it absolute paths.
if ($WorkingDirectory) { $WorkingDirectory = (Resolve-Path -LiteralPath $WorkingDirectory).ProviderPath }

# --- Elevate ----------------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $call = "& $(ConvertTo-PSLiteral $PSCommandPath) -Path $(ConvertTo-PSLiteral $program) -Stage $(ConvertTo-PSLiteral $Stage)"
    if ($ArgumentList) { $call += " -ArgumentList @($(($ArgumentList | ForEach-Object { ConvertTo-PSLiteral $_ }) -join ', '))" }
    if ($WorkingDirectory) { $call += " -WorkingDirectory $(ConvertTo-PSLiteral $WorkingDirectory)" }
    # Keep the window open afterwards so its output can be read.
    $command = "try { $call } finally { Read-Host 'Press Enter to close this window' | Out-Null }; exit `$LASTEXITCODE"

    Write-Host 'Admin rights are needed to create the throwaway account; asking through UAC...'
    try {
        Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', (Get-ExecutionPolicy)
            '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        )
    } catch {
        throw "Could not get admin rights: $($_.Exception.Message)"
    }
    Write-Host 'Continuing in the elevated window.'
    return
}

$computer = $env:COMPUTERNAME
$userName = 'usbx-' + -join (1..8 | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$qualifiedName = "$computer\$userName"
$machine = [ADSI]"WinNT://$computer,computer"
$hideKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$stageRoot = Join-Path $env:ProgramData 'usandbox'
$stageDir = Join-Path $stageRoot $userName

$userCreated = $false
$sid = $null
$exitCode = $null

try {
    # --- Create the account -------------------------------------------------
    $password = New-RandomPassword
    $user = $machine.Create('User', $userName)
    $user.SetPassword($password)
    $user.Put('Description', 'Throwaway account created by usandbox.ps1')
    # SCRIPT | PASSWD_CANT_CHANGE | NORMAL_ACCOUNT | DONT_EXPIRE_PASSWD
    $user.Put('UserFlags', 0x1 -bor 0x40 -bor 0x200 -bor 0x10000)
    $user.SetInfo()
    $userCreated = $true

    $sid = ([Security.Principal.NTAccount] $qualifiedName).Translate([Security.Principal.SecurityIdentifier]).Value

    # New local accounts normally join Users already; make sure, using the SID so
    # it works on non-English Windows.
    $usersGroupName = ([Security.Principal.SecurityIdentifier] 'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
    $usersGroup = [ADSI]"WinNT://$computer/$usersGroupName,group"
    if (-not $usersGroup.IsMember("WinNT://$computer/$userName")) {
        $usersGroup.Add("WinNT://$computer/$userName,user")
    }

    if (-not (Test-Path $hideKey)) { New-Item $hideKey -Force | Out-Null }
    New-ItemProperty -Path $hideKey -Name $userName -Value 0 -PropertyType DWord -Force | Out-Null

    Write-Host "Created throwaway user $qualifiedName ($sid)."

    # --- Stage the program --------------------------------------------------
    if ($Stage -ne 'None') {
        New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
        # Only SYSTEM, Administrators and the throwaway user can see the staged copy.
        icacls $stageDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*${sid}:(OI)(CI)M" | Out-Null
        if ($LASTEXITCODE) { throw "icacls failed on $stageDir (exit code $LASTEXITCODE)." }

        if ($Stage -eq 'File') {
            Copy-Item -LiteralPath $program -Destination $stageDir
        } else {
            Get-ChildItem -LiteralPath (Split-Path $program) -Force |
                Copy-Item -Destination $stageDir -Recurse -Force
        }
        $program = Join-Path $stageDir (Split-Path $program -Leaf)
        Write-Host "Staged program at $program"
    }

    if (-not $WorkingDirectory) { $WorkingDirectory = Split-Path $program }

    # --- Run ----------------------------------------------------------------
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $password = $null

    # Like Start-Process, the arguments are joined with spaces as they are.
    $commandLine = "`"$program`""
    if ($ArgumentList) { $commandLine += ' ' + ($ArgumentList -join ' ') }

    try {
        $proc = [USandbox.SandboxProcess]::Start($userName, $computer, $securePassword, $program, $commandLine, $WorkingDirectory)
    } catch {
        $hint = if ($Stage -eq 'None') { ' If the program is inside your profile, add -Stage File or -Stage Folder.' } else { '' }
        throw "Could not start $program as $qualifiedName`: $($_.Exception.GetBaseException().Message)$hint"
    } finally {
        $securePassword.Dispose()
    }

    Write-Host "Running $program as $qualifiedName (PID $($proc.Id)). Press Ctrl+C to stop it and clean up."

    # Poll instead of WaitForExit() so Ctrl+C still works.
    while (-not $proc.HasExited) { Start-Sleep -Milliseconds 500 }
    $exitCode = $proc.ExitCode
    $proc.Dispose()
    Write-Host "Program exited with code $exitCode."

    # Launchers often start the real program and exit; wait for anything left.
    $announced = $false
    while ($left = @(Get-SandboxProcess)) {
        if (-not $announced) {
            Write-Host "Waiting for processes still running as $qualifiedName`: $(($left | ForEach-Object { "$($_.ProcessName) ($($_.Id))" }) -join ', ')"
            $announced = $true
        }
        Start-Sleep -Seconds 1
    }
}
finally {
    if ($userCreated) {
        Write-Host "Cleaning up $qualifiedName..."

        Invoke-CleanupStep 'stop the remaining processes' {
            Get-SandboxProcess | Stop-Process -Force -ErrorAction SilentlyContinue
        }

        if ($sid) {
            Invoke-CleanupStep 'delete the user profile' {
                # The profile hive unloads shortly after the last process exits.
                for ($i = 0; ; $i++) {
                    $userProfile = Get-CimInstance Win32_UserProfile -Filter "SID = '$sid'"
                    if (-not $userProfile) { break }
                    try {
                        $userProfile | Remove-CimInstance
                        break
                    } catch {
                        if ($i -ge 15) { throw "$($_.Exception.Message) (profile: $($userProfile.LocalPath))" }
                        Start-Sleep -Seconds 1
                    }
                }
            }
        }

        Invoke-CleanupStep 'delete the user account' { $machine.Delete('User', $userName) }

        Invoke-CleanupStep 'remove the sign-in screen entry' {
            Remove-ItemProperty -Path $hideKey -Name $userName -ErrorAction SilentlyContinue
        }

        Invoke-CleanupStep 'remove the staging folder' {
            if (Test-Path -LiteralPath $stageDir) { Remove-Item -LiteralPath $stageDir -Recurse -Force }
            if ((Test-Path -LiteralPath $stageRoot) -and -not (Get-ChildItem -LiteralPath $stageRoot -Force)) {
                Remove-Item -LiteralPath $stageRoot -Force
            }
        }

        Write-Host 'Cleanup finished.'
    }
}

if ($null -ne $exitCode) { exit $exitCode }
