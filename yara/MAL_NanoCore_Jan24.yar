rule MAL_NanoCore_Jan24 {
    meta:
        description = "Detects a NanoCore sample targeting unique strings in an injected/reflected section"
        author = "Matt Green - @mgreen27"
        date = "2024-01-11"
        reference = "https://bazaar.abuse.ch/sample/6ff9daa15f841bf3600d5a9174ab11b921ca8e8f1c9017a1c18afeb514c0f72e/"
        artifact = "Windows.System.VAD"
        arguments = "MappingNameRegex='^$,ProtectionRegex=xrw|-rw,"
        hash = "6ff9daa15f841bf3600d5a9174ab11b921ca8e8f1c9017a1c18afeb514c0f72e"
    strings:
        $x1 = "NanoCore Client.exe" fullword ascii
        $x2 = "NanoCore.ClientPlugin" fullword ascii
        $x3 = "NanoCore.ClientPluginHost" fullword ascii
        $x4 = "NanoCore Client" fullword ascii
    condition:
        uint16(0) == 0x5a4d and
        any of them
}