<#
.SYNOPSIS
    DETECTRAPTOR LAB: removes everything Install-ChromiumExtensionLab.ps1
    added and restores the backed-up browser preference files.

.DESCRIPTION
    DETECTRAPTOR LAB - cleanup for the defensive detection test fixtures.

    Works from %LOCALAPPDATA%\DetectRaptorLabState\state.json when present:

      * Preference files: if a file is unchanged since the install, the
        pre-install backup is restored byte for byte (or the file is deleted
        if the installer created it). If the browser or anything else changed
        it since, only the lab entries are removed, Developer Mode goes back
        to its original value if the installer turned it on, and the backup
        is kept for reference.
      * Extension folders and managed copies are deleted, but only folders
        that contain the DETECTRAPTOR_LAB.txt marker file.
      * The Native Messaging Host key is deleted if its default value points
        into a DetectRaptorLab- folder, and so are any parent keys the
        installer created, once they are empty.
      * Synthetic profile files are deleted, and directories the installer
        created are removed once they are empty.

    It then sweeps the standard Chrome and Edge profiles, the lab folder
    locations and the registry for leftover lab content: entries that carry
    the detectraptor_lab marker or point into a DetectRaptorLab- folder, and
    folders that contain the marker file. That makes it safe to run
    repeatedly, with or without a state file.

.PARAMETER ForceRestoreBackup
    Restore the pre-install backups even when a preference file changed
    after the install. Changes made since then, for example by the browser,
    are lost.

.PARAMETER Force
    Continue even though chrome.exe or msedge.exe is running.

.PARAMETER UserProfile
    Same as for the installer. Defaults to $env:USERPROFILE.

.PARAMETER LocalAppData
    Same as for the installer. Defaults to $env:LOCALAPPDATA, or
    <UserProfile>\AppData\Local when -UserProfile is given.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Uninstall-ChromiumExtensionLab.ps1
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ForceRestoreBackup,

    [switch]$Force,

    [string]$UserProfile = $env:USERPROFILE,

    [string]$LocalAppData
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants (must match Install-ChromiumExtensionLab.ps1)
# ---------------------------------------------------------------------------

$LabMarker = 'DETECTRAPTOR LAB'
$LabFolderPrefix = 'DetectRaptorLab-'
$MarkerFileName = 'DETECTRAPTOR_LAB.txt'
$LabPrefKey = 'detectraptor_lab'
$NativeHostName = 'com.detectraptor.lab.host'
$StateDirName = 'DetectRaptorLabState'
$Utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
$BrowserVendors = @('Google\Chrome', 'Microsoft\Edge')

# ---------------------------------------------------------------------------
# JSON helpers (identical copy in Install-ChromiumExtensionLab.ps1)
#
# Preference files are edited with a small order-preserving JSON reader and
# writer instead of ConvertFrom-Json/ConvertTo-Json: Windows PowerShell 5.1
# rejects keys that differ only by case, and PowerShell 7 turns ISO-8601
# strings into dates. Objects become case-sensitive OrderedDictionary
# instances, arrays become List[object], and every other value keeps its
# original JSON text, so untouched preferences are written back unchanged
# apart from whitespace.
# ---------------------------------------------------------------------------

$JsonTokenPattern = '"[^"\\]*(?:\\.[^"\\]*)*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|[{}\[\]:,]|\S'

function ConvertFrom-LabJsonString {
    # Decodes a JSON string token (including its quotes) to a .NET string.
    param([Parameter(Mandatory = $true)][string]$Token)

    $inner = $Token.Substring(1, $Token.Length - 2)
    if ($inner.IndexOf([char]'\') -lt 0) {
        return $inner
    }
    return [regex]::Replace($inner, '\\(?:u([0-9a-fA-F]{4})|(.))', {
            param($m)
            if ($m.Groups[1].Success) {
                return [string][char][Convert]::ToInt32($m.Groups[1].Value, 16)
            }
            switch -CaseSensitive ($m.Groups[2].Value) {
                'b' { return [string][char]8 }
                'f' { return [string][char]12 }
                'n' { return "`n" }
                'r' { return "`r" }
                't' { return "`t" }
                default { return $m.Groups[2].Value }
            }
        })
}

function ConvertTo-LabJsonString {
    # Encodes a .NET string as a JSON string token.
    param([AllowEmptyString()][string]$Value)

    $escaped = [regex]::Replace($Value, '["\\\x00-\x1f]', {
            param($m)
            switch ([int][char]$m.Value) {
                8 { '\b' }
                9 { '\t' }
                10 { '\n' }
                12 { '\f' }
                13 { '\r' }
                34 { '\"' }
                92 { '\\' }
                default { '\u{0:x4}' -f [int][char]$m.Value }
            }
        })
    return '"' + $escaped + '"'
}

function ConvertFrom-LabJson {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    if ($Text.Length -gt 0 -and $Text[0] -eq [char]0xFEFF) {
        $Text = $Text.Substring(1)
    }
    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    $root = $null
    $haveRoot = $false
    $key = $null
    $expectKey = $false
    $expectColon = $false

    foreach ($match in [regex]::Matches($Text, $JsonTokenPattern)) {
        $token = $match.Value
        $first = $token[0]
        if ($expectColon) {
            if ($token -ne ':') {
                throw "Invalid JSON: expected ':' at offset $($match.Index)."
            }
            $expectColon = $false
            continue
        }
        if ($token -eq ',') {
            if ($stack.Count -eq 0) {
                throw "Invalid JSON: unexpected ',' at offset $($match.Index)."
            }
            $expectKey = $stack.Peek() -is [System.Collections.Specialized.OrderedDictionary]
            continue
        }
        if ($token -eq '}' -or $token -eq ']') {
            if ($stack.Count -eq 0) {
                throw "Invalid JSON: unexpected '$token' at offset $($match.Index)."
            }
            $null = $stack.Pop()
            $expectKey = $false
            continue
        }
        if ($expectKey) {
            if ($first -ne '"' -or $token.Length -lt 2) {
                throw "Invalid JSON: expected a property name at offset $($match.Index)."
            }
            $key = ConvertFrom-LabJsonString -Token $token
            $expectKey = $false
            $expectColon = $true
            continue
        }

        if ($token -eq '{') {
            $value = New-Object System.Collections.Specialized.OrderedDictionary
        }
        elseif ($token -eq '[') {
            $value = New-Object 'System.Collections.Generic.List[object]'
        }
        elseif (($first -eq '"' -and $token.Length -ge 2) -or $first -eq '-' -or
            ($first -ge '0' -and $first -le '9') -or
            $token -eq 'true' -or $token -eq 'false' -or $token -eq 'null') {
            $value = $token
        }
        else {
            throw "Invalid JSON: unexpected '$token' at offset $($match.Index)."
        }

        if ($stack.Count -eq 0) {
            if ($haveRoot) {
                throw "Invalid JSON: unexpected data at offset $($match.Index)."
            }
            $root = $value
            $haveRoot = $true
        }
        else {
            $parent = $stack.Peek()
            if ($parent -is [System.Collections.Specialized.OrderedDictionary]) {
                $parent[$key] = $value
            }
            else {
                $parent.Add($value)
            }
        }
        if ($token -eq '{' -or $token -eq '[') {
            $stack.Push($value)
            $expectKey = ($token -eq '{')
        }
    }

    if (-not $haveRoot -or $stack.Count -ne 0 -or $expectColon) {
        throw 'Invalid JSON: the document is incomplete.'
    }
    return , $root
}

function Write-LabJsonNode {
    param($Builder, $Node, [bool]$Pretty, [int]$Depth)

    if ($Node -is [System.Collections.Specialized.OrderedDictionary]) {
        # get_Count(), not .Count: PowerShell resolves .Count to a key named
        # "count" when the dictionary has one.
        if ($Node.get_Count() -eq 0) {
            [void]$Builder.Append('{}')
            return
        }
        [void]$Builder.Append('{')
        $separator = ''
        foreach ($entry in $Node.GetEnumerator()) {
            [void]$Builder.Append($separator)
            $separator = ','
            if ($Pretty) {
                [void]$Builder.Append("`r`n").Append('  ' * ($Depth + 1))
            }
            [void]$Builder.Append((ConvertTo-LabJsonString -Value ([string]$entry.Key)))
            [void]$Builder.Append(':')
            if ($Pretty) {
                [void]$Builder.Append(' ')
            }
            if ($entry.Value -is [string]) {
                [void]$Builder.Append($entry.Value)
            }
            else {
                Write-LabJsonNode -Builder $Builder -Node $entry.Value -Pretty $Pretty -Depth ($Depth + 1)
            }
        }
        if ($Pretty) {
            [void]$Builder.Append("`r`n").Append('  ' * $Depth)
        }
        [void]$Builder.Append('}')
    }
    elseif ($Node -is [System.Collections.IList]) {
        if ($Node.Count -eq 0) {
            [void]$Builder.Append('[]')
            return
        }
        [void]$Builder.Append('[')
        $separator = ''
        foreach ($item in $Node) {
            [void]$Builder.Append($separator)
            $separator = ','
            if ($Pretty) {
                [void]$Builder.Append("`r`n").Append('  ' * ($Depth + 1))
            }
            if ($item -is [string]) {
                [void]$Builder.Append($item)
            }
            else {
                Write-LabJsonNode -Builder $Builder -Node $item -Pretty $Pretty -Depth ($Depth + 1)
            }
        }
        if ($Pretty) {
            [void]$Builder.Append("`r`n").Append('  ' * $Depth)
        }
        [void]$Builder.Append(']')
    }
    elseif ($null -eq $Node) {
        [void]$Builder.Append('null')
    }
    else {
        # Leaf values are already JSON text.
        [void]$Builder.Append([string]$Node)
    }
}

function ConvertTo-LabJson {
    param($Node, [switch]$Pretty)

    $builder = New-Object System.Text.StringBuilder
    Write-LabJsonNode -Builder $builder -Node $Node -Pretty ([bool]$Pretty) -Depth 0
    if ($Pretty) {
        [void]$builder.Append("`r`n")
    }
    return $builder.ToString()
}

function ConvertTo-LabJsonNode {
    # Converts PowerShell values (ordered hashtables, arrays, strings, bools,
    # numbers) into the node format used by the reader and writer above.
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return 'null'
    }
    if ($Value -is [string]) {
        return (ConvertTo-LabJsonString -Value $Value)
    }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $node = New-Object System.Collections.Specialized.OrderedDictionary
        foreach ($name in $Value.Keys) {
            $node[[string]$name] = ConvertTo-LabJsonNode -Value $Value[$name]
        }
        return , $node
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $Value) {
            $list.Add((ConvertTo-LabJsonNode -Value $item))
        }
        return , $list
    }
    if ($Value -is [int] -or $Value -is [long]) {
        return [System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    throw "Cannot convert a value of type $($Value.GetType().FullName) to JSON."
}

function Get-LabJsonChild {
    # Returns the object stored under $Key, optionally creating it.
    param($Parent, [string]$Key, [switch]$Create)

    if (-not ($Parent -is [System.Collections.Specialized.OrderedDictionary])) {
        return $null
    }
    $child = $null
    if ($Parent.Contains($Key)) {
        $child = $Parent[$Key]
    }
    if ($child -is [System.Collections.Specialized.OrderedDictionary]) {
        return $child
    }
    if (-not $Create) {
        return $null
    }
    if ($null -ne $child -and -not ($child -is [string] -and $child -eq 'null')) {
        throw "Preference '$Key' exists but is not a JSON object; not modifying it."
    }
    $child = New-Object System.Collections.Specialized.OrderedDictionary
    $Parent[$Key] = $child
    return $child
}

# ---------------------------------------------------------------------------
# Cleanup helpers
# ---------------------------------------------------------------------------

function Write-LabTextFile {
    # Writes UTF-8 without a BOM: Velociraptor's parse_json() cannot read a
    # preference file that starts with one.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )

    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [System.IO.Directory]::Exists($parent)) {
        $null = [System.IO.Directory]::CreateDirectory($parent)
    }
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Get-LabFileHash {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

$actions = New-Object 'System.Collections.Generic.List[object]'

function Add-LabAction {
    param([string]$Item, [string]$Action)

    $actions.Add((New-Object PSObject -Property ([ordered]@{ Action = $Action; Item = $Item })))
}

function Remove-LabDirectory {
    # Deletes a lab folder, but only when it carries the marker file.
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.IO.Directory]::Exists($Path)) {
        return 'Already absent'
    }
    if (-not [System.IO.File]::Exists((Join-Path $Path $MarkerFileName))) {
        return "Skipped: no $MarkerFileName marker file"
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
    return 'Deleted lab folder'
}

function Remove-EmptyDirectory {
    param([string]$Path, [string]$Reason)

    if (-not $Path -or -not [System.IO.Directory]::Exists($Path)) {
        return
    }
    if ($null -ne (Get-ChildItem -LiteralPath $Path -Force | Select-Object -First 1)) {
        return
    }
    Remove-Item -LiteralPath $Path -Force
    Add-LabAction -Item $Path -Action $Reason
}

function Remove-EmptyRegistryKey {
    param([string]$Path)

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        return
    }
    $key = Get-Item -LiteralPath $Path
    $isEmpty = $key.SubKeyCount -eq 0 -and $key.ValueCount -eq 0
    $key.Close()
    if ($isEmpty) {
        Remove-Item -LiteralPath $Path -Force
        Add-LabAction -Item $Path -Action 'Deleted empty registry key created by the installer'
    }
}

function Remove-LabNativeHostKey {
    # Deletes the lab Native Messaging Host key, but only when its default
    # value points into a lab folder.
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return 'Already absent'
    }
    $properties = Get-ItemProperty -LiteralPath $Path
    $target = [string]$properties.'(default)'
    if ($target.IndexOf($LabFolderPrefix, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        return "Skipped: default value does not point into a $LabFolderPrefix folder"
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
    return 'Deleted Native Messaging Host registry key'
}

function Test-LabPreferenceEntry {
    # A lab entry has an ID the installer recorded, the detectraptor_lab
    # marker, a path into a DetectRaptorLab- folder (which also catches
    # browser-written entries from loading a lab folder by hand) or a cached
    # manifest whose description carries the DETECTRAPTOR LAB banner.
    param([string]$ExtensionId, $Entry, $KnownIds)

    if ($KnownIds -contains $ExtensionId) {
        return $true
    }
    if (-not ($Entry -is [System.Collections.Specialized.OrderedDictionary])) {
        return $false
    }
    if ($Entry.Contains($LabPrefKey)) {
        return $true
    }
    $path = [string]$Entry['path']
    if ($path.IndexOf($LabFolderPrefix, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        return $true
    }
    $manifest = $Entry['manifest']
    if ($manifest -is [System.Collections.Specialized.OrderedDictionary]) {
        $description = [string]$manifest['description']
        if ($description.IndexOf($LabMarker, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Remove-LabPreferenceEntries {
    # Removes lab entries from one preference file and optionally puts
    # Developer Mode back. Writes the file (after backing it up) only when
    # something changed.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        $KnownIds,
        [bool]$RestoreDeveloperMode,
        $DeveloperModeOriginal,
        [string]$BackupPath
    )

    $root = ConvertFrom-LabJson -Text ([System.IO.File]::ReadAllText($Path))
    $extensionsNode = Get-LabJsonChild -Parent $root -Key 'extensions'
    $settingsNode = Get-LabJsonChild -Parent $extensionsNode -Key 'settings'
    $removed = 0
    if ($null -ne $settingsNode) {
        $labIds = @($settingsNode.get_Keys() | Where-Object {
                Test-LabPreferenceEntry -ExtensionId $_ -Entry $settingsNode[$_] -KnownIds $KnownIds
            })
        foreach ($id in $labIds) {
            $settingsNode.Remove($id)
            $removed++
        }
    }

    $developerModeRestored = $false
    if ($RestoreDeveloperMode) {
        $uiNode = Get-LabJsonChild -Parent $extensionsNode -Key 'ui'
        if ($null -ne $uiNode -and [string]$uiNode['developer_mode'] -eq 'true') {
            if ($null -eq $DeveloperModeOriginal) {
                $uiNode.Remove('developer_mode')
            }
            else {
                $uiNode['developer_mode'] = [string]$DeveloperModeOriginal
            }
            $developerModeRestored = $true
        }
    }

    if ($removed -gt 0 -or $developerModeRestored) {
        $newText = ConvertTo-LabJson -Node $root
        # Re-read our own output so a writer bug can never leave a broken file.
        $null = ConvertFrom-LabJson -Text $newText
        if ($BackupPath -and -not [System.IO.File]::Exists($BackupPath)) {
            $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($BackupPath))
            Copy-Item -LiteralPath $Path -Destination $BackupPath
        }
        Write-LabTextFile -Path $Path -Content $newText
    }
    return (New-Object PSObject -Property ([ordered]@{
                Removed = $removed
                DeveloperModeRestored = $developerModeRestored
            }))
}

function Get-LabBackupName {
    param([string]$Vendor, [string]$ProfileLabel, [string]$FileName)

    return ('{0}-{1}-{2}.bak' -f ($Vendor -replace '\\', '_'), ($ProfileLabel -replace '[^A-Za-z0-9._-]', '_'), ($FileName -replace ' ', '_'))
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host "$LabMarker - removing Chromium extension lab content" -ForegroundColor Cyan

if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
    throw 'This cleanup targets Windows Chrome/Edge profile state. Run it on the Windows lab VM.'
}
if (-not $UserProfile) {
    throw 'USERPROFILE is not set; pass -UserProfile.'
}
$UserProfile = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($UserProfile)
if (-not $LocalAppData) {
    if ($PSBoundParameters.ContainsKey('UserProfile')) {
        $LocalAppData = Join-Path $UserProfile 'AppData\Local'
    }
    else {
        $LocalAppData = $env:LOCALAPPDATA
    }
}
if (-not $LocalAppData) {
    throw 'LOCALAPPDATA is not set; pass -LocalAppData.'
}
$LocalAppData = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($LocalAppData)
$publicRoot = $env:PUBLIC
if (-not $publicRoot) {
    $publicRoot = 'C:\Users\Public'
}

$running = @(Get-Process -Name 'chrome', 'msedge' -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    $message = ('Chrome or Edge is running ({0} process(es)). Close it first: the browser rewrites its profile files on exit. Edge can keep running in the background (startup boost), so check Task Manager. Use -Force to continue anyway.' -f $running.Count)
    if (-not $Force) {
        throw $message
    }
    Write-Warning $message
}

$stateDir = Join-Path $LocalAppData $StateDirName
$statePath = Join-Path $stateDir 'state.json'
$sweepBackupDir = Join-Path $stateDir 'cleanup-backups'
$knownIds = New-Object 'System.Collections.Generic.List[string]'
$restoredBackups = New-Object 'System.Collections.Generic.List[string]'
$labState = $null
if ([System.IO.File]::Exists($statePath)) {
    $labState = [System.IO.File]::ReadAllText($statePath) | ConvertFrom-Json
}

if ($null -ne $labState) {
    foreach ($record in $labState.PreferenceFiles) {
        foreach ($id in $record.ExtensionIds) {
            $knownIds.Add([string]$id)
        }
    }

    # Preference files first, while the lab folders still exist.
    foreach ($record in $labState.PreferenceFiles) {
        $path = [string]$record.Path
        if (-not [System.IO.File]::Exists($path)) {
            Add-LabAction -Item $path -Action 'Already absent'
            continue
        }
        $unchanged = $record.InstalledSha256 -and ((Get-LabFileHash -Path $path) -eq [string]$record.InstalledSha256)
        $backupPath = [string]$record.BackupPath
        $haveBackup = $record.OriginalExisted -and $backupPath -and [System.IO.File]::Exists($backupPath)
        if (($unchanged -or $ForceRestoreBackup) -and $haveBackup) {
            Copy-Item -LiteralPath $backupPath -Destination $path -Force
            $restoredBackups.Add($backupPath)
            Add-LabAction -Item $path -Action 'Restored the pre-install backup'
            continue
        }
        if (($unchanged -or $ForceRestoreBackup) -and -not $record.OriginalExisted) {
            Remove-Item -LiteralPath $path -Force
            Add-LabAction -Item $path -Action 'Deleted (created by the installer)'
            continue
        }

        $cleanupBackup = Join-Path $sweepBackupDir (Get-LabBackupName -Vendor ([string]$record.Browser) -ProfileLabel ([string]$record.Profile) -FileName (Split-Path -Leaf $path))
        $result = Remove-LabPreferenceEntries -Path $path -KnownIds $knownIds -RestoreDeveloperMode ([bool]$record.DeveloperModeChanged) -DeveloperModeOriginal $record.DeveloperModeOriginal -BackupPath $cleanupBackup
        $detail = 'file changed since the install'
        if ($result.DeveloperModeRestored) {
            $detail += '; Developer Mode reset to its original value'
        }
        if ($haveBackup) {
            $detail += ('; pre-install backup kept at {0}' -f $backupPath)
        }
        Add-LabAction -Item $path -Action ('Removed {0} lab entries ({1})' -f $result.Removed, $detail)
    }

    foreach ($directory in $labState.ManagedCopies) {
        if ($directory) {
            Add-LabAction -Item $directory -Action (Remove-LabDirectory -Path $directory)
        }
    }
    foreach ($directory in $labState.Folders) {
        if ($directory) {
            Add-LabAction -Item $directory -Action (Remove-LabDirectory -Path $directory)
        }
    }

    foreach ($registryKey in $labState.RegistryKeys) {
        if (-not $registryKey) {
            continue
        }
        Add-LabAction -Item $registryKey.Path -Action (Remove-LabNativeHostKey -Path $registryKey.Path)
        foreach ($createdKey in @($registryKey.CreatedKeys | Sort-Object -Property Length -Descending)) {
            if ($createdKey -and $createdKey -ne $registryKey.Path) {
                Remove-EmptyRegistryKey -Path $createdKey
            }
        }
    }

    foreach ($file in $labState.CreatedFiles) {
        if ($file -and [System.IO.File]::Exists($file)) {
            Remove-Item -LiteralPath $file -Force
            Add-LabAction -Item $file -Action 'Deleted (created by the installer)'
        }
    }
}
else {
    Add-LabAction -Item $statePath -Action 'No state file; sweeping for marked lab content only'
}

# Sweep the standard locations for anything left over, with or without state.
foreach ($vendor in $BrowserVendors) {
    $userData = [System.IO.Path]::Combine($LocalAppData, $vendor, 'User Data')
    if (-not [System.IO.Directory]::Exists($userData)) {
        continue
    }
    foreach ($profileDir in @(Get-ChildItem -LiteralPath $userData -Directory -Force -ErrorAction SilentlyContinue)) {
        foreach ($fileName in @('Secure Preferences', 'Preferences')) {
            $path = Join-Path $profileDir.FullName $fileName
            if (-not [System.IO.File]::Exists($path)) {
                continue
            }
            $cleanupBackup = Join-Path $sweepBackupDir (Get-LabBackupName -Vendor $vendor -ProfileLabel $profileDir.Name -FileName $fileName)
            try {
                $result = Remove-LabPreferenceEntries -Path $path -KnownIds $knownIds -BackupPath $cleanupBackup
                if ($result.Removed -gt 0) {
                    Add-LabAction -Item $path -Action ('Removed {0} leftover lab entries (backup: {1}); Developer Mode left as it is' -f $result.Removed, $cleanupBackup)
                }
            }
            catch {
                Write-Warning ('Could not check {0}: {1}' -f $path, $_.Exception.Message)
            }
        }

        $extensionsDir = Join-Path $profileDir.FullName 'Extensions'
        if (-not [System.IO.Directory]::Exists($extensionsDir)) {
            continue
        }
        foreach ($idDir in @(Get-ChildItem -LiteralPath $extensionsDir -Directory -Force -ErrorAction SilentlyContinue)) {
            $removedCopy = $false
            foreach ($versionDir in @(Get-ChildItem -LiteralPath $idDir.FullName -Directory -Force -ErrorAction SilentlyContinue)) {
                if ([System.IO.File]::Exists((Join-Path $versionDir.FullName $MarkerFileName))) {
                    Remove-Item -LiteralPath $versionDir.FullName -Recurse -Force
                    Add-LabAction -Item $versionDir.FullName -Action 'Deleted leftover lab managed copy'
                    $removedCopy = $true
                }
            }
            if ($removedCopy) {
                Remove-EmptyDirectory -Path $idDir.FullName -Reason 'Deleted empty extension directory'
            }
        }
    }
}

$sweepRoots = @(
    (Join-Path $UserProfile 'Downloads')
    (Join-Path $UserProfile 'Documents')
    (Join-Path $LocalAppData 'Temp')
    $env:TEMP
    $LocalAppData
    (Join-Path $publicRoot 'Documents')
) | Where-Object { $_ } | Select-Object -Unique
foreach ($sweepRoot in $sweepRoots) {
    if (-not [System.IO.Directory]::Exists($sweepRoot)) {
        continue
    }
    foreach ($directory in @(Get-ChildItem -LiteralPath $sweepRoot -Directory -Filter ($LabFolderPrefix + '*') -Force -ErrorAction SilentlyContinue)) {
        if ([System.IO.File]::Exists((Join-Path $directory.FullName $MarkerFileName))) {
            Remove-Item -LiteralPath $directory.FullName -Recurse -Force
            Add-LabAction -Item $directory.FullName -Action 'Deleted leftover lab folder'
        }
    }
}

foreach ($vendor in $BrowserVendors) {
    $keyPath = 'HKCU:\Software\{0}\NativeMessagingHosts\{1}' -f $vendor, $NativeHostName
    if (Test-Path -LiteralPath $keyPath) {
        Add-LabAction -Item $keyPath -Action (Remove-LabNativeHostKey -Path $keyPath)
    }
}

# Directories the installer created (synthetic profiles, Extensions\<id>,
# parents of lab folders) go last, and only when empty.
if ($null -ne $labState) {
    foreach ($directory in @($labState.CreatedDirectories | Sort-Object -Property Length -Descending)) {
        Remove-EmptyDirectory -Path $directory -Reason 'Deleted empty directory created by the installer'
    }
}

foreach ($backup in $restoredBackups) {
    if ([System.IO.File]::Exists($backup)) {
        Remove-Item -LiteralPath $backup -Force
    }
}
foreach ($leaf in @('state.json', 'expected-results.csv')) {
    $file = Join-Path $stateDir $leaf
    if ([System.IO.File]::Exists($file)) {
        Remove-Item -LiteralPath $file -Force
        Add-LabAction -Item $file -Action 'Deleted lab state'
    }
}
Remove-EmptyDirectory -Path (Join-Path $stateDir 'backups') -Reason 'Deleted empty backup directory'
Remove-EmptyDirectory -Path $stateDir -Reason 'Deleted empty lab state directory'
if ([System.IO.Directory]::Exists($stateDir)) {
    Add-LabAction -Item $stateDir -Action 'Kept: holds backups of preference files that changed after the install; delete it when no longer needed'
}

Write-Host ''
if ($actions.Count -eq 0) {
    Write-Host "Nothing to remove: no $LabMarker content found." -ForegroundColor Green
}
else {
    $actions | Format-Table -AutoSize -Wrap -Property Action, Item | Out-String -Width 220 | Write-Host
}
Write-Host 'Re-run DetectRaptor.Windows.Detection.ChromiumExtensionPersistence to confirm: no rows should reference DetectRaptorLab- paths, the lab extension IDs or com.detectraptor.lab.host.'
