<#
.SYNOPSIS
    DETECTRAPTOR LAB: installs inert Chromium extension persistence fixtures
    for testing DetectRaptor.Windows.Detection.ChromiumExtensionPersistence.

.DESCRIPTION
    DETECTRAPTOR LAB - defensive detection test content. NOT MALWARE.
    Run it on a disposable lab VM.

    Writes harmless Manifest V3 extension folders to typical sideload
    locations (Downloads, %TEMP%, %LOCALAPPDATA%, Documents and
    C:\Users\Public) and registers them in a Chrome and/or Edge profile the
    way a sideload looks on disk: extensions.settings.<id> entries carrying
    the install location, path and permissions, with Developer Mode turned
    on. It also registers an inert Native Messaging Host under HKCU.

    Every extension is inert. Its service worker only logs a
    "DETECTRAPTOR LAB" line. The permissions in each manifest are declared
    only so the detector has something to score and are never used. The
    Native Messaging Host names an executable that does not exist.

    Profile files are edited offline, so the browser must not be running;
    the script refuses to continue while chrome.exe or msedge.exe runs
    unless -Force is given. No preference MACs are computed. On a
    standalone (workgroup) machine Chrome and Edge drop the lab entries and
    reset Developer Mode the next time they start, so collect with
    Velociraptor before starting the browser. See README.md.

    Every file it modifies is backed up first, and everything it creates is
    recorded in %LOCALAPPDATA%\DetectRaptorLabState\state.json. Undo it all
    with Uninstall-ChromiumExtensionLab.ps1.

.PARAMETER Browser
    Chrome (default), Edge or Both.

.PARAMETER ProfileName
    Profile directory under "User Data" that receives the entries. Defaults
    to "Default".

.PARAMETER ProfilePath
    Full path of a profile directory to use instead of
    <LocalAppData>\<vendor>\User Data\<ProfileName>. Only valid with a single
    browser. If the path is outside the artifact's default globs, the script
    prints the PreferenceTargets value to collect with.

.PARAMETER SyntheticProfile
    Create the profile directory (and User Data) if it does not exist, so the
    lab works on a VM without Chrome or Edge installed. A profile that
    already exists is used as it is, with a backup.

.PARAMETER PreferenceFile
    Which preference file receives the entries. Auto (default) uses the file
    that already holds extensions.settings, falling back to
    "Secure Preferences", where Chrome and Edge keep them on standalone
    Windows.

.PARAMETER Case
    Use cases to install: A-H are extensions, N is the Native Messaging Host.
    Defaults to all of them.

.PARAMETER IncludeLegacyStateKey
    Also write "state": 1 in each entry, as Chromium did before it retired
    the key in 2025. Both fixture formats represent enabled extensions.

.PARAMETER FilesOnly
    Only write the extension folders for cases A, B, D, E, F and G so they can
    be loaded by hand with chrome://extensions > Load unpacked. Makes no
    profile or registry changes.

.PARAMETER Force
    Continue even though chrome.exe or msedge.exe is running.

.PARAMETER UserProfile
    Base for Downloads and Documents. Defaults to $env:USERPROFILE.

.PARAMETER LocalAppData
    Base for the browser profiles, %TEMP% (<LocalAppData>\Temp) and the lab
    state. Defaults to $env:LOCALAPPDATA, or <UserProfile>\AppData\Local when
    -UserProfile is given.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-ChromiumExtensionLab.ps1

    Installs all cases into the Chrome "Default" profile.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-ChromiumExtensionLab.ps1 -Browser Both -SyntheticProfile

    Installs into Chrome and Edge, creating synthetic profiles where a
    browser is not installed.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Chrome', 'Edge', 'Both')]
    [string]$Browser = 'Chrome',

    [string]$ProfileName = 'Default',

    [string]$ProfilePath,

    [switch]$SyntheticProfile,

    [ValidateSet('Auto', 'SecurePreferences', 'Preferences')]
    [string]$PreferenceFile = 'Auto',

    [ValidateSet('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'N')]
    [string[]]$Case = @('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'N'),

    [switch]$IncludeLegacyStateKey,

    [switch]$FilesOnly,

    [switch]$Force,

    [string]$UserProfile = $env:USERPROFILE,

    [string]$LocalAppData
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

$LabMarker = 'DETECTRAPTOR LAB'
# Every lab folder name starts with this prefix; the uninstaller relies on it.
$LabFolderPrefix = 'DetectRaptorLab-'
$MarkerFileName = 'DETECTRAPTOR_LAB.txt'
# Extra key written into each lab extensions.settings entry. Chromium ignores it.
$LabPrefKey = 'detectraptor_lab'
$NativeHostName = 'com.detectraptor.lab.host'
$StateDirName = 'DetectRaptorLabState'
$Utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false

# RSA public keys generated for this lab (no private keys exist in this
# repository). A manifest "key" fixes the extension ID, so cases C, G and H
# get the same ID on every machine.
$PackedEdgeKey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtw6zHGi/bMyiJ85Ldw0vru51EqO/G+fVAxehGqzdAYO8KGnMXkeozCjNt/lFKwEzvptm1BMaIWWjJoILcAKis46XCqHDGuGWP4orFyOxBvAxlZni9mk+KwlHxhtM0uUT5Gx17ZXj8aRUEYo9PyyiXFMiVKdjnpy0/JJwZLIRof8RN7wLhYSygB3TUDsVJbeFAm/lkKDbZtTkBQ+INXc5dkRNhfBIf+yCfa9iIBvw8/0t+eKHkg2Gq8SmCgZUySLpKbqZ2Vo3Ln8doWMJf+Y0Tzpn0hC7zcdUY63zsodiHYzVAVdrzo6cguuFQVz4S8UBLXwrTRVyazLAa1I99FXZlwIDAQAB'
$IdReuseKey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAttrdiHt49r16gsaS7PIlMo4tLtOn6gI8Z/PI0WypD++rclIh2HCVaiSm5RKdv4I3PKMJ66YRYyOZufLMLkGlz9ru2sECG2u3r49/6sHx31cuTSxZcSaSNHafikU6jMpeCwwY4nwkuAeMMSzTsvMGMjyIsF6oCnlDcs/TQMt7CWLNHjazAt35yMDdpqjGNY9Hi/2i4F1WFPOxB980USMn/yr0G0USGffUQK44rilDJ2jBxDCgrnVVfwUfSyDK76QnqflJIDMMJiXdlgFrSEQivj/OvmPUeRY3q7Nk5efYTPMEhEIBDuAwW90H3eRBpaTzFvog53JLXrSe07YYvh0PswIDAQAB'
$StoreControlKey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyN0vMmBIvcH56QBb3xMqP33CgT2mkbSwOLgzT/0boB3LhjEe2P39WiaMVPzlxvGaE45Gro3rslDnsI329qCOQ4cTk13QT1XnK0hE9SXOUMVuNKZeBOqFV5fPqHssIhdWo0xF+qMXVf+71QR/vUd1B3SXdb+Zjxbeh8V/epqtWB2svpg167+LRJz93JOfLXcIQVAOBnzcMQdrsCp08eh3vo9VnVT44EPTBEBtwQJVnDDfmWsOYhIGwv21cRHURw06KHa3ODhrWL8nIpgf+SqjaN+dCU6m0rnshgui6NEkDMmG5sF0aTmvEUYQRSNMa+631hwt/mC8E20xFGjcwZuRwQIDAQAB'

# Default regexes of DetectRaptor.Windows.Detection.ChromiumExtensionPersistence.
# They are only used to print estimated scores; nothing here is enforced.
$SuspiciousPathRegex = '(?i)[\\/](Users[\\/]Public|Temp|TMP|Downloads|Desktop|ProgramData|Windows[\\/]Temp)([\\/]|$)'
$PowerfulPermissionRegex = '(?i)(cookies|history|tabs|debugger|nativeMessaging|webRequest|webRequestBlocking|scripting|management|downloads|clipboardRead|clipboardWrite|geolocation|proxy)'
$BroadHostRegex = '(?i)(<all_urls>|\*://\*/\*|https?://\*/\*)'
$MasqueradeNameRegex = '(?i)^\s*(Google\s+Chrome|Chrome|Chromium|Microsoft\s+Edge|Edge|Google|Microsoft|Brave|Opera)(\s+(Update|Updater|Helper|Service|Security))?\s*$'
$MinScore = 40
$NativeHostMinScore = 20

$BrowserInfo = @{
    Chrome = @{
        Vendor = 'Google\Chrome'
        Process = 'chrome'
        StoreUpdateUrl = 'https://clients2.google.com/service/update2/crx'
    }
    Edge = @{
        Vendor = 'Microsoft\Edge'
        Process = 'msedge'
        StoreUpdateUrl = 'https://edge.microsoft.com/extensionwebstorebase/v1/crx'
    }
}

# ---------------------------------------------------------------------------
# JSON helpers (identical copy in Uninstall-ChromiumExtensionLab.ps1)
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
# File, ID and state helpers
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

function New-LabDirectory {
    # Creates a directory and any missing parents, recording each directory
    # created so the uninstaller can remove it again once it is empty.
    param([Parameter(Mandatory = $true)][string]$Path)

    $missing = New-Object 'System.Collections.Generic.List[string]'
    $current = [System.IO.Path]::GetFullPath($Path)
    while ($current -and -not [System.IO.Directory]::Exists($current)) {
        $missing.Insert(0, $current)
        $current = [System.IO.Path]::GetDirectoryName($current)
    }
    foreach ($directory in $missing) {
        $null = [System.IO.Directory]::CreateDirectory($directory)
        $State.CreatedDirectories.Add($directory)
    }
}

function Get-LabFileHash {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function ConvertTo-ChromiumExtensionId {
    # crx_file::id_util::GenerateId: the first 16 bytes of SHA-256, hex
    # encoded with the alphabet a-p instead of 0-9a-f.
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($Bytes)
    }
    finally {
        $sha256.Dispose()
    }
    $chars = New-Object char[] 32
    for ($i = 0; $i -lt 16; $i++) {
        $chars[2 * $i] = [char](97 + ($hash[$i] -shr 4))
        $chars[2 * $i + 1] = [char](97 + ($hash[$i] -band 15))
    }
    return (-join $chars)
}

function Get-UnpackedExtensionId {
    # crx_file::id_util::GenerateIdForPath: Chromium on Windows hashes the
    # UTF-16LE path with the drive letter upper-cased.
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -match '^[a-z]:') {
        $Path = $Path.Substring(0, 1).ToUpperInvariant() + $Path.Substring(1)
    }
    return (ConvertTo-ChromiumExtensionId -Bytes ([System.Text.Encoding]::Unicode.GetBytes($Path)))
}

function Get-KeyExtensionId {
    # An extension with a manifest key gets the ID of the decoded public key.
    param([Parameter(Mandatory = $true)][string]$Key)

    return (ConvertTo-ChromiumExtensionId -Bytes ([Convert]::FromBase64String($Key)))
}

function Get-ChromiumTimestamp {
    # Microseconds since 1601-01-01 UTC, the format of first_install_time.
    $remainder = [long]0
    return [string][System.Math]::DivRem([DateTime]::UtcNow.ToFileTimeUtc(), [long]10, [ref]$remainder)
}

function Save-LabState {
    if (-not [System.IO.Directory]::Exists($stateDir)) {
        $null = [System.IO.Directory]::CreateDirectory($stateDir)
    }
    $State['UpdatedUtc'] = [DateTime]::UtcNow.ToString('o')
    [System.IO.File]::WriteAllText($statePath, (ConvertTo-Json -InputObject $State -Depth 8), $Utf8NoBom)
}

function Test-LabStateHasContent {
    return ($State.Folders.Count + $State.ManagedCopies.Count + $State.PreferenceFiles.Count +
        $State.RegistryKeys.Count + $State.CreatedFiles.Count + $State.CreatedDirectories.Count) -gt 0
}

# ---------------------------------------------------------------------------
# Lab content
# ---------------------------------------------------------------------------

function New-LabCase {
    param([Parameter(Mandatory = $true)][hashtable]$Definition)

    $properties = [ordered]@{
        Id = $null
        Title = $null
        Location = 4
        FromWebStore = $false
        Folder = $null
        Name = $null
        LocalizedName = $null
        DefaultLocale = $null
        Version = '1.0.0'
        Permissions = @()
        HostPermissions = @()
        Key = $null
        ManagedCopyVersion = $null
        ExtensionId = $null
    }
    foreach ($name in $Definition.Keys) {
        $properties[$name] = $Definition[$name]
    }
    return (New-Object PSObject -Property $properties)
}

function Get-LabMarkerText {
    param([Parameter(Mandatory = $true)][string]$Description)

    $lines = @(
        "$LabMarker - inert detection test fixture. NOT MALWARE."
        ''
        $Description
        ''
        ('Created {0} by Install-ChromiumExtensionLab.ps1 to test the Velociraptor' -f [DateTime]::UtcNow.ToString('u'))
        'artifact DetectRaptor.Windows.Detection.ChromiumExtensionPersistence.'
        'Nothing here runs code beyond a console.log() line.'
        'Remove with Uninstall-ChromiumExtensionLab.ps1, which only deletes folders'
        'that contain this file.'
    )
    return (($lines -join "`r`n") + "`r`n")
}

function Get-LabBackgroundScript {
    param([Parameter(Mandatory = $true)]$LabCase)

    $lines = @(
        "// $LabMarker - inert detection test fixture. NOT MALWARE."
        "// Case $($LabCase.Id): $($LabCase.Title)"
        '// Written by Install-ChromiumExtensionLab.ps1 to exercise the Velociraptor'
        '// artifact DetectRaptor.Windows.Detection.ChromiumExtensionPersistence.'
        '// This service worker registers no listeners, calls no extension APIs and'
        '// makes no network requests. The permissions in manifest.json are declared'
        '// only so the detector has something to score; they are never used.'
        ("console.log('{0}: inert lab extension (case {1}), no functionality.');" -f $LabMarker, $LabCase.Id)
    )
    return (($lines -join "`r`n") + "`r`n")
}

function New-LabManifest {
    param(
        [Parameter(Mandatory = $true)]$LabCase,
        [string]$Version,
        [string]$UpdateUrl,
        [switch]$IncludeKey
    )

    if (-not $Version) {
        $Version = $LabCase.Version
    }
    $manifest = [ordered]@{}
    $manifest['manifest_version'] = 3
    $manifest['name'] = $LabCase.Name
    $manifest['version'] = $Version
    $manifest['description'] = '{0} - inert detection test fixture (case {1}), not malware. Declared permissions are never used.' -f $LabMarker, $LabCase.Id
    if ($LabCase.DefaultLocale) {
        $manifest['default_locale'] = $LabCase.DefaultLocale
    }
    $manifest['background'] = [ordered]@{ service_worker = 'background.js' }
    if (@($LabCase.Permissions).Count -gt 0) {
        $manifest['permissions'] = @($LabCase.Permissions)
    }
    if (@($LabCase.HostPermissions).Count -gt 0) {
        $manifest['host_permissions'] = @($LabCase.HostPermissions)
    }
    if ($IncludeKey -and $LabCase.Key) {
        $manifest['key'] = $LabCase.Key
    }
    if ($UpdateUrl) {
        $manifest['update_url'] = $UpdateUrl
    }
    return $manifest
}

function Write-LabExtensionFiles {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)]$LabCase,
        [Parameter(Mandatory = $true)]$Manifest
    )

    $markerPath = Join-Path $Directory $MarkerFileName
    if ([System.IO.Directory]::Exists($Directory) -and -not [System.IO.File]::Exists($markerPath)) {
        throw "Refusing to write into an existing folder that has no $MarkerFileName marker: $Directory"
    }
    New-LabDirectory -Path $Directory
    Write-LabTextFile -Path $markerPath -Content (Get-LabMarkerText -Description ('Case {0}: {1}' -f $LabCase.Id, $LabCase.Title))
    Write-LabTextFile -Path (Join-Path $Directory 'manifest.json') -Content (ConvertTo-LabJson -Node (ConvertTo-LabJsonNode -Value $Manifest) -Pretty)
    Write-LabTextFile -Path (Join-Path $Directory 'background.js') -Content (Get-LabBackgroundScript -LabCase $LabCase)
    if ($LabCase.DefaultLocale -and $LabCase.LocalizedName -and $Manifest['name'] -like '__MSG_*') {
        $messages = [ordered]@{
            appName = [ordered]@{
                message = $LabCase.LocalizedName
                description = "$LabMarker - localized extension name, exercises __MSG_ name resolution."
            }
        }
        $messagesPath = [System.IO.Path]::Combine($Directory, '_locales', $LabCase.DefaultLocale, 'messages.json')
        Write-LabTextFile -Path $messagesPath -Content (ConvertTo-LabJson -Node (ConvertTo-LabJsonNode -Value $messages) -Pretty)
    }
}

function Write-LabManagedCopy {
    # Writes a copy of the extension into <profile>\Extensions\<id>\<version>_0,
    # where the browser keeps packed (CRX and Web Store) installs. Returns the
    # manifest, which the browser also caches in the preference entry.
    param(
        [Parameter(Mandatory = $true)][string]$ProfileDirectory,
        [Parameter(Mandatory = $true)]$LabCase,
        [string]$UpdateUrl
    )

    $versionDir = '{0}_0' -f $LabCase.ManagedCopyVersion
    $copyDir = [System.IO.Path]::Combine($ProfileDirectory, 'Extensions', $LabCase.ExtensionId, $versionDir)
    $manifest = New-LabManifest -LabCase $LabCase -Version $LabCase.ManagedCopyVersion -UpdateUrl $UpdateUrl -IncludeKey
    $State.ManagedCopies.Add($copyDir)
    Write-LabExtensionFiles -Directory $copyDir -LabCase $LabCase -Manifest $manifest
    return $manifest
}

function New-LabPreferenceEntry {
    # Builds an extensions.settings.<id> entry with the fields current
    # Chromium writes (ExtensionPrefs::PopulateExtensionInfoPrefs). The manifest
    # is only cached for packed installs, as in Chromium.
    param(
        [Parameter(Mandatory = $true)]$LabCase,
        [Parameter(Mandatory = $true)][string]$ExtensionPath,
        $Manifest,
        [Parameter(Mandatory = $true)][string]$InstallTime,
        [bool]$LegacyState
    )

    $loadedFromFolder = $LabCase.Location -eq 4 -or $LabCase.Location -eq 8
    if ($loadedFromFolder) {
        $creationFlags = 38
    }
    elseif ($LabCase.FromWebStore) {
        $creationFlags = 9
    }
    else {
        $creationFlags = 1
    }
    $permissions = [ordered]@{
        api = @($LabCase.Permissions)
        explicit_host = @($LabCase.HostPermissions)
        manifest_permissions = @()
        scriptable_host = @()
    }

    $entry = [ordered]@{}
    $entry['account_extension_type'] = 0
    $entry['active_permissions'] = $permissions
    $entry['commands'] = [ordered]@{}
    $entry['content_settings'] = @()
    $entry['creation_flags'] = $creationFlags
    $entry['disable_reasons'] = @()
    $entry['first_install_time'] = $InstallTime
    $entry['from_webstore'] = [bool]$LabCase.FromWebStore
    $entry['granted_permissions'] = $permissions
    $entry['incognito_content_settings'] = @()
    $entry['incognito_preferences'] = [ordered]@{}
    $entry['last_update_time'] = $InstallTime
    $entry['location'] = [int]$LabCase.Location
    if ($null -ne $Manifest) {
        $entry['manifest'] = $Manifest
    }
    if ($loadedFromFolder) {
        $entry['newAllowFileAccess'] = $true
    }
    $entry['path'] = $ExtensionPath
    $entry['preferences'] = [ordered]@{}
    $entry['regular_only_preferences'] = [ordered]@{}
    $entry['service_worker_registration_info'] = [ordered]@{ version = $LabCase.Version }
    if ($LegacyState) {
        $entry['state'] = 1
    }
    $entry['was_installed_by_default'] = $false
    $entry['was_installed_by_oem'] = $false
    $entry['withholding_permissions'] = $false
    $entry[$LabPrefKey] = '{0} test entry (case {1}); remove with Uninstall-ChromiumExtensionLab.ps1' -f $LabMarker, $LabCase.Id
    return $entry
}

function Select-LabPreferenceFile {
    param(
        [Parameter(Mandatory = $true)][string]$ProfileDirectory,
        [Parameter(Mandatory = $true)][string]$Mode
    )

    $secure = Join-Path $ProfileDirectory 'Secure Preferences'
    $regular = Join-Path $ProfileDirectory 'Preferences'
    if ($Mode -eq 'SecurePreferences') {
        return $secure
    }
    if ($Mode -eq 'Preferences') {
        return $regular
    }
    # Auto: use the file that already holds extensions.settings. That is
    # Secure Preferences on standalone Windows, and Preferences where tracked
    # preferences are not enforced (for example domain-joined machines).
    foreach ($candidate in @($secure, $regular)) {
        if (-not [System.IO.File]::Exists($candidate)) {
            continue
        }
        $root = ConvertFrom-LabJson -Text ([System.IO.File]::ReadAllText($candidate))
        $settings = Get-LabJsonChild -Parent (Get-LabJsonChild -Parent $root -Key 'extensions') -Key 'settings'
        if ($null -ne $settings) {
            return $candidate
        }
    }
    return $secure
}

function Test-LabEncryptedHash {
    # True when the file has protection.macs.extensions.settings_encrypted_hash,
    # which removes the artifact's +5 MissingEncryptedHash weight.
    param($Root)

    $node = Get-LabJsonChild -Parent (Get-LabJsonChild -Parent (Get-LabJsonChild -Parent $Root -Key 'protection') -Key 'macs') -Key 'extensions'
    if ($null -eq $node -or -not $node.Contains('settings_encrypted_hash')) {
        return $false
    }
    $value = $node['settings_encrypted_hash']
    if ($value -is [System.Collections.ICollection]) {
        return ($value.get_Count() -gt 0)
    }
    return (@('null', 'false', '""') -notcontains [string]$value)
}

function Test-LabDefaultGlobCoverage {
    param([string]$ProfileDirectory, [string]$Vendor)

    $pattern = '^C:\\Users\\[^\\]+\\AppData\\Local\\' + [regex]::Escape($Vendor) + '\\User Data\\[^\\]+$'
    return ($ProfileDirectory -match $pattern)
}

function Get-LabLocationName {
    param([int]$Location)

    switch ($Location) {
        1 { return 'INTERNAL' }
        4 { return 'UNPACKED' }
        8 { return 'COMMAND_LINE' }
        default { return ('LOCATION_{0}' -f $Location) }
    }
}

function Get-LabSeverity {
    param([int]$Score)

    if ($Score -ge 90) { return 'HIGH' }
    if ($Score -ge 60) { return 'MEDIUM' }
    return 'LOW'
}

function Get-LabEstimate {
    # Mirrors the RiskScore arithmetic of the artifact's Extensions source with
    # its default parameters. Estimate only: the real numbers come from
    # running the artifact.
    param(
        [Parameter(Mandatory = $true)]$LabCase,
        [Parameter(Mandatory = $true)][string]$EntryPath,
        [bool]$DeveloperMode,
        [bool]$EncryptedHashPresent,
        [bool]$ManagedCopy
    )

    $location = [int]$LabCase.Location
    $unpacked = $location -eq 4
    $sideloaded = ($location -eq 4) -or ($location -eq 8) -or
        ((@(1, 2, 3, 6) -contains $location) -and -not $LabCase.FromWebStore)
    $permissionText = (@($LabCase.Permissions) + @($LabCase.HostPermissions)) -join ' '
    $debugger = @($LabCase.Permissions) -ccontains 'debugger'
    $name = $LabCase.Name
    if ($LabCase.LocalizedName) {
        $name = $LabCase.LocalizedName
    }
    $masquerade = $name -match $MasqueradeNameRegex

    $score = 0
    $signals = New-Object 'System.Collections.Generic.List[string]'
    if ($unpacked) { $score += 40; $signals.Add('Unpacked') }
    # Every generated entry has empty disable_reasons or explicit state=1.
    $signals.Add('Enabled')
    if ($unpacked) { $score += 5 }
    if ($DeveloperMode) {
        $signals.Add('DevMode')
        if ($unpacked) { $score += 5 }
    }
    if ($unpacked -and $EntryPath -match '^[A-Za-z]:[\\/]') { $score += 5 }
    if ($unpacked -and $EntryPath -notmatch '(?i)[\\/]User Data[\\/][^\\/]+[\\/]Extensions[\\/]') { $score += 5 }
    if ($EntryPath -match $SuspiciousPathRegex) { $score += 20; $signals.Add('SuspiciousPath') }
    if ($permissionText -match $PowerfulPermissionRegex) { $score += 10; $signals.Add('PowerfulAPIs') }
    if ($permissionText -match $BroadHostRegex) { $score += 10; $signals.Add('BroadHosts') }
    if (@($LabCase.Permissions) -ccontains 'nativeMessaging') { $signals.Add('NativeMessaging') }
    # The artifact only looks for a manifest key in the preference entry, and
    # Chromium only caches the manifest there for packed installs, where the
    # key is not scored.
    if ($location -eq 1 -and $LabCase.Key) { $signals.Add('ManifestKey') }
    if ($ManagedCopy) {
        $signals.Add('ManagedCopy')
        if ($unpacked) { $score += 25 }
    }
    if ($unpacked -and -not $EncryptedHashPresent) { $score += 5; $signals.Add('MissingEncryptedHash') }
    if ($sideloaded) { $signals.Add('Sideloaded') }
    if ($masquerade) { $signals.Add('MasqueradeName') }
    if ($debugger) { $score += 10; $signals.Add('Debugger') }
    if ($sideloaded -and $debugger) { $score += 20 }
    if ($sideloaded -and $masquerade) { $score += 30 }
    if ($sideloaded -and $masquerade -and $debugger) { $score += 20 }

    return (New-Object PSObject -Property ([ordered]@{
                Score = $score
                Severity = (Get-LabSeverity -Score $score)
                Returned = ($score -ge $MinScore)
                Signals = ($signals -join ' ')
            }))
}

function New-LabResultRow {
    param(
        [string]$CaseId,
        [string]$BrowserName,
        [string]$ProfileLabel,
        [string]$Source,
        [string]$Identifier,
        [string]$Name,
        [string]$Location,
        [string]$Path,
        [int]$Score,
        [string]$Severity,
        [bool]$Returned,
        [string]$Signals
    )

    return (New-Object PSObject -Property ([ordered]@{
                Case = $CaseId
                Browser = $BrowserName
                Profile = $ProfileLabel
                Source = $Source
                ExtensionId = $Identifier
                Name = $Name
                Location = $Location
                Path = $Path
                EstimatedRiskScore = $Score
                EstimatedSeverity = $Severity
                ReturnedByDefault = $Returned
                Signals = $Signals
            }))
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host "$LabMarker - Chromium extension persistence lab (inert test fixtures, not malware)" -ForegroundColor Cyan

if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
    throw 'This lab writes Windows Chrome/Edge profile state. Run it on a Windows lab VM.'
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
if ($ProfileName -match '[\\/]') {
    throw '-ProfileName is a directory name such as "Default" or "Profile 1"; use -ProfilePath for a full path.'
}

if ($Browser -eq 'Both') {
    $browsers = @('Chrome', 'Edge')
}
elseif ($Browser -eq 'Edge') {
    $browsers = @('Edge')
}
else {
    $browsers = @('Chrome')
}
if ($ProfilePath -and $browsers.Count -gt 1) {
    throw '-ProfilePath names a single profile; use it with -Browser Chrome or -Browser Edge.'
}
$selected = @($Case | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique)

$stateDir = Join-Path $LocalAppData $StateDirName
$statePath = Join-Path $stateDir 'state.json'
$backupDir = Join-Path $stateDir 'backups'
if ([System.IO.File]::Exists($statePath)) {
    throw "A lab install is already recorded in $statePath. Run Uninstall-ChromiumExtensionLab.ps1 first, then install again."
}

if (-not $FilesOnly) {
    $processNames = @($browsers | ForEach-Object { $BrowserInfo[$_].Process })
    $running = @(Get-Process -Name $processNames -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) {
        $message = ('{0} is running ({1} process(es)). Close it first: the browser rewrites its profile files on exit and would discard the lab entries. Edge can keep running in the background (startup boost), so check Task Manager. Use -Force to continue anyway.' -f ($browsers -join '/'), $running.Count)
        if (-not $Force) {
            throw $message
        }
        Write-Warning $message
    }
}

$downloadsDir = Join-Path $UserProfile 'Downloads'
$documentsDir = Join-Path $UserProfile 'Documents'
# <LocalAppData>\Temp is %TEMP% for a normal logon, without 8.3 short names.
$tempDir = Join-Path $LocalAppData 'Temp'
$publicRoot = $env:PUBLIC
if (-not $publicRoot) {
    $publicRoot = 'C:\Users\Public'
}
$publicDocumentsDir = Join-Path $publicRoot 'Documents'

# Resolve and check the target profiles before anything is written.
$targets = New-Object 'System.Collections.Generic.List[object]'
if (-not $FilesOnly) {
    foreach ($browserName in $browsers) {
        $info = $BrowserInfo[$browserName]
        if ($ProfilePath) {
            $profileDir = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($ProfilePath)
        }
        else {
            $profileDir = [System.IO.Path]::Combine($LocalAppData, $info.Vendor, 'User Data', $ProfileName)
        }
        if (-not [System.IO.Directory]::Exists($profileDir) -and -not $SyntheticProfile) {
            throw "$browserName profile not found: $profileDir. Start $browserName once to create it, or re-run with -SyntheticProfile to create a synthetic profile on a bare VM."
        }
        $targets.Add((New-Object PSObject -Property ([ordered]@{
                        Browser = $browserName
                        Info = $info
                        ProfileDirectory = $profileDir
                    })))
    }
}

$cases = @(
    New-LabCase @{
        Id = 'A'
        Title = 'Unit 42 Helix-style sideload: unpacked "Google Chrome" with debugger in Downloads'
        Location = 4
        Folder = Join-Path $downloadsDir 'DetectRaptorLab-A-folderextension'
        Name = 'Google Chrome'
        Version = '1.6.112'
        Permissions = @('alarms', 'clipboardRead', 'clipboardWrite', 'cookies', 'debugger', 'downloads', 'history',
            'offscreen', 'scripting', 'storage', 'system.display', 'tabs', 'webNavigation')
        HostPermissions = @('<all_urls>')
    }
    New-LabCase @{
        Id = 'B'
        Title = 'Unpacked __MSG_ name resolving to "Chrome Update", with debugger, in %TEMP%'
        Location = 4
        Folder = Join-Path $tempDir 'DetectRaptorLab-B-chrome-update'
        Name = '__MSG_appName__'
        LocalizedName = 'Chrome Update'
        DefaultLocale = 'en'
        Version = '3.2.0'
        Permissions = @('debugger', 'storage')
    }
    New-LabCase @{
        Id = 'C'
        Title = 'Packed off-store install (INTERNAL, from_webstore false) named "Microsoft Edge"'
        Location = 1
        Name = 'Microsoft Edge'
        Version = '1.0.4'
        Permissions = @('scripting', 'storage', 'tabs')
        HostPermissions = @('<all_urls>')
        Key = $PackedEdgeKey
        ManagedCopyVersion = '1.0.4'
    }
    New-LabCase @{
        Id = 'D'
        Title = 'Unpacked debugger-only extension with a benign name in %LOCALAPPDATA%'
        Location = 4
        Folder = Join-Path $LocalAppData 'DetectRaptorLab-D-page-timing'
        Name = 'DetectRaptor Lab Page Timing'
        Version = '0.9.0'
        Permissions = @('debugger')
    }
    New-LabCase @{
        Id = 'E'
        Title = 'Benign control: unpacked developer extension, storage only, in Documents'
        Location = 4
        Folder = Join-Path $documentsDir 'DetectRaptorLab-E-dev-notes'
        Name = 'DetectRaptor Lab Dev Notes'
        Version = '0.1.0'
        Permissions = @('storage')
    }
    New-LabCase @{
        Id = 'F'
        Title = 'Command-line (--load-extension) sideload "Chrome Helper" with nativeMessaging in C:\Users\Public'
        Location = 8
        Folder = Join-Path $publicDocumentsDir 'DetectRaptorLab-F-chrome-helper'
        Name = 'Chrome Helper'
        Version = '2.0.1'
        Permissions = @('nativeMessaging', 'storage')
    }
    New-LabCase @{
        Id = 'G'
        Title = 'Unpacked extension reusing the ID of an installed copy (manifest key + managed copy)'
        Location = 4
        Folder = Join-Path $LocalAppData 'DetectRaptorLab-G-tab-sync'
        Name = 'DetectRaptor Lab Tab Sync'
        Version = '2.4.1'
        Permissions = @('storage', 'tabs')
        Key = $IdReuseKey
        ManagedCopyVersion = '2.4.0'
    }
    New-LabCase @{
        Id = 'H'
        Title = 'Negative control: Web Store install (from_webstore true) with debugger'
        Location = 1
        FromWebStore = $true
        Name = 'DetectRaptor Lab Store Control'
        Version = '3.1.0'
        Permissions = @('debugger', 'storage', 'tabs')
        HostPermissions = @('<all_urls>')
        Key = $StoreControlKey
        ManagedCopyVersion = '3.1.0'
    }
)

$caseById = @{}
foreach ($labCase in $cases) {
    if ($labCase.Key) {
        $labCase.ExtensionId = Get-KeyExtensionId -Key $labCase.Key
    }
    else {
        $labCase.ExtensionId = Get-UnpackedExtensionId -Path $labCase.Folder
    }
    $caseById[$labCase.Id] = $labCase
}
$extensionCases = @($cases | Where-Object { $selected -contains $_.Id })
$folderCases = @($extensionCases | Where-Object { $_.Location -ne 1 })

$State = [ordered]@{
    Marker = $LabMarker
    Tool = 'Install-ChromiumExtensionLab.ps1'
    CreatedUtc = [DateTime]::UtcNow.ToString('o')
    UserProfile = $UserProfile
    LocalAppData = $LocalAppData
    Browsers = $browsers
    Cases = $selected
    FilesOnly = [bool]$FilesOnly
    LegacyStateKey = [bool]$IncludeLegacyStateKey
    Folders = New-Object 'System.Collections.Generic.List[string]'
    ManagedCopies = New-Object 'System.Collections.Generic.List[string]'
    PreferenceFiles = New-Object 'System.Collections.Generic.List[object]'
    RegistryKeys = New-Object 'System.Collections.Generic.List[object]'
    CreatedFiles = New-Object 'System.Collections.Generic.List[string]'
    CreatedDirectories = New-Object 'System.Collections.Generic.List[string]'
}
$rows = New-Object 'System.Collections.Generic.List[object]'

try {
    # Extension folders for unpacked and command-line cases, shared by both
    # browsers. Packed cases live inside each profile instead.
    foreach ($labCase in $folderCases) {
        $State.Folders.Add($labCase.Folder)
        $manifest = New-LabManifest -LabCase $labCase -IncludeKey:([bool]$labCase.Key)
        Write-LabExtensionFiles -Directory $labCase.Folder -LabCase $labCase -Manifest $manifest
    }
    Save-LabState

    if ($FilesOnly) {
        Write-Host ''
        Write-Host 'Extension folders written (no profile or registry changes):' -ForegroundColor Cyan
        $folderCases | Format-Table -AutoSize -Property Id, ExtensionId, Name, Folder | Out-String -Width 220 | Write-Host
        Write-Host 'Load them with chrome://extensions (or edge://extensions) > Developer mode > Load unpacked.'
        Write-Host 'The browser then writes genuine, MAC-protected entries (all as UNPACKED, including case F).'
        Write-Host 'Close the browser before collecting. Remove with Uninstall-ChromiumExtensionLab.ps1.'
        return
    }

    if ($extensionCases.Count -eq 0) {
        # Only case N was selected: leave the browser profiles alone.
        $targets.Clear()
    }
    foreach ($target in $targets) {
        $browserName = $target.Browser
        $info = $target.Info
        $profileDir = $target.ProfileDirectory
        $profileLabel = Split-Path -Leaf $profileDir

        if (-not [System.IO.Directory]::Exists($profileDir)) {
            New-LabDirectory -Path $profileDir
            $profileMarker = Join-Path $profileDir $MarkerFileName
            $State.CreatedFiles.Add($profileMarker)
            Write-LabTextFile -Path $profileMarker -Content (Get-LabMarkerText -Description "Synthetic $browserName profile, created because no real profile existed.")
            Write-Host "Created synthetic $browserName profile: $profileDir"
        }

        $prefPath = Select-LabPreferenceFile -ProfileDirectory $profileDir -Mode $PreferenceFile
        $originalExisted = [System.IO.File]::Exists($prefPath)
        if ($originalExisted) {
            $root = ConvertFrom-LabJson -Text ([System.IO.File]::ReadAllText($prefPath))
            if (-not ($root -is [System.Collections.Specialized.OrderedDictionary])) {
                throw "$prefPath does not hold a JSON object; not modifying it."
            }
        }
        else {
            $root = New-Object System.Collections.Specialized.OrderedDictionary
        }

        $extensionsNode = Get-LabJsonChild -Parent $root -Key 'extensions' -Create
        $settingsNode = Get-LabJsonChild -Parent $extensionsNode -Key 'settings' -Create
        $uiNode = Get-LabJsonChild -Parent $extensionsNode -Key 'ui' -Create
        $devModeOriginal = $null
        if ($uiNode.Contains('developer_mode')) {
            $devModeOriginal = [string]$uiNode['developer_mode']
        }
        $devModeChanged = $devModeOriginal -ne 'true'
        $encryptedHashPresent = Test-LabEncryptedHash -Root $root
        $installTime = Get-ChromiumTimestamp
        $ids = New-Object 'System.Collections.Generic.List[string]'

        foreach ($labCase in $extensionCases) {
            $manifestInPrefs = $null
            $managedCopy = $false
            if ($labCase.Location -eq 1) {
                $updateUrl = $null
                if ($labCase.FromWebStore) {
                    $updateUrl = $info.StoreUpdateUrl
                }
                $manifestInPrefs = Write-LabManagedCopy -ProfileDirectory $profileDir -LabCase $labCase -UpdateUrl $updateUrl
                $managedCopy = $true
                $entryPath = '{0}\{1}_0' -f $labCase.ExtensionId, $labCase.ManagedCopyVersion
            }
            else {
                if ($labCase.ManagedCopyVersion) {
                    # Case G: an installed copy with the same ID already exists.
                    $null = Write-LabManagedCopy -ProfileDirectory $profileDir -LabCase $labCase -UpdateUrl $info.StoreUpdateUrl
                    $managedCopy = $true
                }
                $entryPath = $labCase.Folder
            }

            $entry = New-LabPreferenceEntry -LabCase $labCase -ExtensionPath $entryPath -Manifest $manifestInPrefs -InstallTime $installTime -LegacyState ([bool]$IncludeLegacyStateKey)
            $settingsNode[$labCase.ExtensionId] = ConvertTo-LabJsonNode -Value $entry
            $ids.Add($labCase.ExtensionId)

            $estimate = Get-LabEstimate -LabCase $labCase -EntryPath $entryPath -DeveloperMode $true -EncryptedHashPresent $encryptedHashPresent -ManagedCopy $managedCopy
            $displayName = $labCase.Name
            if ($labCase.LocalizedName) {
                $displayName = '{0} -> {1}' -f $labCase.Name, $labCase.LocalizedName
            }
            $rows.Add((New-LabResultRow -CaseId $labCase.Id -BrowserName $browserName -ProfileLabel $profileLabel -Source 'Extensions' -Identifier $labCase.ExtensionId -Name $displayName -Location (Get-LabLocationName -Location $labCase.Location) -Path $entryPath -Score $estimate.Score -Severity $estimate.Severity -Returned $estimate.Returned -Signals $estimate.Signals))
        }
        if ($devModeChanged) {
            $uiNode['developer_mode'] = 'true'
        }

        $newText = ConvertTo-LabJson -Node $root
        # Re-read our own output so a writer bug can never leave a broken file.
        $null = ConvertFrom-LabJson -Text $newText

        $record = [ordered]@{
            Browser = $browserName
            Profile = $profileLabel
            ProfileDirectory = $profileDir
            Path = $prefPath
            OriginalExisted = $originalExisted
            BackupPath = $null
            OriginalSha256 = $null
            InstalledSha256 = $null
            DeveloperModeChanged = $devModeChanged
            DeveloperModeOriginal = $devModeOriginal
            ExtensionIds = $ids
        }
        if ($originalExisted) {
            if (-not [System.IO.Directory]::Exists($backupDir)) {
                $null = [System.IO.Directory]::CreateDirectory($backupDir)
            }
            $backupName = '{0}-{1}-{2}.bak' -f $browserName, ($profileLabel -replace '[^A-Za-z0-9._-]', '_'), ((Split-Path -Leaf $prefPath) -replace ' ', '_')
            $backupPath = Join-Path $backupDir $backupName
            Copy-Item -LiteralPath $prefPath -Destination $backupPath -Force
            $record['BackupPath'] = $backupPath
            $record['OriginalSha256'] = Get-LabFileHash -Path $prefPath
        }
        $State.PreferenceFiles.Add($record)
        Save-LabState

        Write-LabTextFile -Path $prefPath -Content $newText
        $record['InstalledSha256'] = Get-LabFileHash -Path $prefPath
        Save-LabState
        Write-Host ('{0}: wrote {1} lab entries to {2}' -f $browserName, $ids.Count, $prefPath)
        if ($record['BackupPath']) {
            Write-Host ('{0}: original backed up to {1}' -f $browserName, $record['BackupPath'])
        }
        if ($encryptedHashPresent) {
            Write-Host ('{0}: this profile has protection.macs.extensions.settings_encrypted_hash, so unpacked cases score 5 less than the README table.' -f $browserName)
        }
        if (-not (Test-LabDefaultGlobCoverage -ProfileDirectory $profileDir -Vendor $info.Vendor)) {
            $globBase = $profileDir -replace '\\', '/'
            Write-Warning ("$profileDir is outside the artifact's default PreferenceTargets globs. Collect with PreferenceTargets set to:`nBrowser,Glob`n{0},{1}/Secure Preferences`n{0},{1}/Preferences" -f $browserName, $globBase)
        }
    }

    if ($selected -contains 'N') {
        # Case N: Native Messaging Host registration. The manifest lives in
        # %TEMP% and names an executable that does not exist.
        $hostDir = Join-Path $tempDir 'DetectRaptorLab-N-nativehost'
        $hostManifestPath = Join-Path $hostDir ($NativeHostName + '.json')
        $hostExeName = 'detectraptor-lab-host-missing.exe'
        $hostExePath = Join-Path $hostDir $hostExeName
        $hostMarker = Join-Path $hostDir $MarkerFileName
        if ([System.IO.Directory]::Exists($hostDir) -and -not [System.IO.File]::Exists($hostMarker)) {
            throw "Refusing to write into an existing folder that has no $MarkerFileName marker: $hostDir"
        }
        $State.Folders.Add($hostDir)
        New-LabDirectory -Path $hostDir
        Write-LabTextFile -Path $hostMarker -Content (Get-LabMarkerText -Description 'Case N: inert Native Messaging Host manifest. The executable it names intentionally does not exist, so nothing can be launched.')
        $hostManifest = [ordered]@{
            name = $NativeHostName
            description = "$LabMarker - inert Native Messaging Host for detection testing. The host executable intentionally does not exist."
            path = $hostExeName
            type = 'stdio'
            allowed_origins = @(('chrome-extension://{0}/' -f $caseById['F'].ExtensionId))
        }
        Write-LabTextFile -Path $hostManifestPath -Content (ConvertTo-LabJson -Node (ConvertTo-LabJsonNode -Value $hostManifest) -Pretty)

        # Same arithmetic as the artifact's NativeMessagingHosts source. The
        # manifest exists and its name matches the key, so those weights are 0.
        $hostScore = 0
        $hostSignals = New-Object 'System.Collections.Generic.List[string]'
        if ($hostManifestPath -match $SuspiciousPathRegex) { $hostScore += 25; $hostSignals.Add('SuspiciousManifestPath') }
        if ($hostExePath -match $SuspiciousPathRegex) { $hostScore += 25; $hostSignals.Add('SuspiciousExecutablePath') }
        if (-not [System.IO.File]::Exists($hostExePath)) { $hostScore += 10; $hostSignals.Add('ExecutableMissing') }
        $hostScore += 5
        $hostSignals.Add('AllowedOrigins')
        if ($hostScore -ge 50) { $hostSeverity = 'HIGH' } elseif ($hostScore -ge 25) { $hostSeverity = 'MEDIUM' } else { $hostSeverity = 'LOW' }

        foreach ($browserName in $browsers) {
            $info = $BrowserInfo[$browserName]
            $createdKeys = New-Object 'System.Collections.Generic.List[string]'
            $keyPath = 'HKCU:\Software\{0}\NativeMessagingHosts\{1}' -f $info.Vendor, $NativeHostName
            $State.RegistryKeys.Add([ordered]@{ Path = $keyPath; CreatedKeys = $createdKeys })
            # Create missing keys one level at a time; New-Item -Force on an
            # existing registry key would wipe its values.
            $current = 'HKCU:\Software'
            foreach ($segment in (@($info.Vendor -split '\\') + @('NativeMessagingHosts', $NativeHostName))) {
                $current = '{0}\{1}' -f $current, $segment
                if (-not (Test-Path -LiteralPath $current)) {
                    $null = New-Item -Path $current
                    $createdKeys.Add($current)
                }
            }
            Save-LabState
            Set-Item -LiteralPath $keyPath -Value $hostManifestPath
            $rows.Add((New-LabResultRow -CaseId 'N' -BrowserName $browserName -ProfileLabel '-' -Source 'NativeMessagingHosts' -Identifier $NativeHostName -Name $NativeHostName -Location 'HKCU' -Path $hostManifestPath -Score $hostScore -Severity $hostSeverity -Returned ($hostScore -ge $NativeHostMinScore) -Signals ($hostSignals -join ' ')))
        }
        Save-LabState
    }
}
finally {
    if (Test-LabStateHasContent) {
        Save-LabState
    }
}

$expectedPath = Join-Path $stateDir 'expected-results.csv'
$rows | Export-Csv -LiteralPath $expectedPath -NoTypeInformation

Write-Host ''
Write-Host "$LabMarker installed. ESTIMATED artifact results (default parameters, computed from the artifact's weights, not measured):" -ForegroundColor Cyan
$rows | Format-Table -AutoSize -Property Case, Browser, Profile, Source, Location, Name, EstimatedRiskScore, EstimatedSeverity, ReturnedByDefault | Out-String -Width 220 | Write-Host
$rows | Format-Table -AutoSize -Wrap -Property Case, Browser, ExtensionId, Path, Signals | Out-String -Width 220 | Write-Host
Write-Host "Saved to $expectedPath; state and backups are in $stateDir."
Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Cyan
Write-Host '  1. Do NOT start Chrome/Edge yet. On a standalone machine the browser drops these unsigned entries at startup.'
Write-Host '  2. Collect from an elevated prompt, for example:'
Write-Host '       velociraptor.exe --definitions <folder with ChromiumExtensionPersistence.yaml> artifacts collect DetectRaptor.Windows.Detection.ChromiumExtensionPersistence --format=jsonl'
Write-Host '     Add --args ShowAll=Y to also see case H, which stays below MinScore.'
if ($selected -contains 'G') {
    Write-Host ('     Add --args ExpectedStoreExtensionIdRegex=^{0}$ to exercise the +30 StoreIdLoadedUnpacked weight on case G.' -f $caseById['G'].ExtensionId)
}
Write-Host '  3. Clean up: powershell -ExecutionPolicy Bypass -File .\Uninstall-ChromiumExtensionLab.ps1'
