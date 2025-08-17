import "math"
rule FIREEYE_RT_APT_Backdoor_Win_Gorat_Memory {
    meta:
		description = "Identifies GoRat malware in memory based on strings."
		author = "FireEye"
		id = "16fb1db7-711c-5d8d-9203-738c94f253fe"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE (Gorat)/production/yara/APT_Backdoor_Win_GoRat_Memory.yar#L4-L27"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "3b926b5762e13ceec7ac3a61e85c93bb"
		logic_hash = "88272e59325d106f96d6b6f1d57daf968823c1e760067dee0334c66c521ce8c2"
		score = 75
		quality = 75
		tags = ""
		rev = 1

	strings:
		$murica = "murica" fullword
		$rat1 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
		$rat2 = "rat.(*Core).generateBeacon" fullword
		$rat3 = "rat.gJitter" fullword
		$rat4 = "rat/comms.(*protectedChannel).SendCmdResponse" fullword
		$rat5 = "rat/modules/filemgmt.(*acquire).NewCommandExecution" fullword
		$rat6 = "rat/modules/latlisten.(*latlistensrv).handleCmd" fullword
		$rat7 = "rat/modules/netsweeper.(*netsweeperRunner).runSweep" fullword
		$rat8 = "rat/modules/netsweeper.(*Pinger).listen" fullword
		$rat9 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
		$rat10 = "rat/platforms/win/dyloader.(*memoryLoader).ExecutePluginFunction" fullword
		$rat11 = "rat/platforms/win/modules/namedpipe.(*dummy).Open" fullword
		$winblows = "rat/platforms/win.(*winblows).GetStage" fullword

	condition:
		$winblows or #murica > 10 or 3 of ( $rat* )
}
rule TRELLIX_ARC_Sodinokobi : RANSOMWARE {
    meta:
		description = "This rule detect Sodinokobi Ransomware in memory in old samples and perhaps future."
		author = "McAfee ATR team"
		id = "dd05ce31-9699-50a9-944c-5883340791af"
		date = "2025-08-01"
		modified = "2025-03-18"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/ransomware/RANSOM_Sodinokibi.yar#L32-L53"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "f25039ac743223756461bbeeb349c674473608f9959bf3c79ce4a7587fde3ab2"
		score = 75
		quality = 70
		tags = "RANSOMWARE"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Sodinokibi"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		version = "1.0"

	strings:
		$a = { 40 0F B6 C8 89 4D FC 8A 94 0D FC FE FF FF 0F B6 C2 03 C6 0F B6 F0 8A 84 35 FC FE FF FF 88 84 0D FC FE FF FF 88 94 35 FC FE FF FF 0F B6 8C 0D FC FE FF FF }
		$b = { 0F B6 C2 03 C8 8B 45 14 0F B6 C9 8A 8C 0D FC FE FF FF 32 0C 07 88 08 40 89 45 14 8B 45 FC 83 EB 01 75 AA }

	condition:
		all of them
}
rule VOLEXITY_Webshell_Jsp_Converge : FILE MEMORY CVE_2022_26134 {
    meta:
		description = "Detects CONVERGE - a file upload webshell observed in incident involving compromise of Confluence server via CVE-2022-26134."
		author = "threatintel@volexity.com"
		id = "2a74678e-cb00-567c-a2e0-2e095f3e5ee8"
		date = "2022-06-01"
		modified = "2024-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L1-L21"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "bb48516342eddd48c35e6db0eb74f95e116dc723503552b99ba721b5bdb391e5"
		score = 75
		quality = 80
		tags = "FILE, MEMORY, CVE-2022-26134"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6788
		version = 5

	strings:
		$s1 = "if (request.getParameter(\"name\")!=null && request.getParameter(\"name\").length()!=0){" ascii

	condition:
		$s1
}
rule VOLEXITY_Webshell_Java_Realcmd : FILE MEMORY {
    meta:
		description = "Detects the RealCMD webshell, one of the payloads for BEHINDER."
		author = "threatintel@volexity.com"
		id = "60b30ccc-bcfa-51e6-a3f5-88037d19213e"
		date = "2022-06-01"
		modified = "2024-07-30"
		reference = "https://github.com/Freakboy/Behinder/blob/master/src/main/java/vip/youwe/sheller/payload/java/RealCMD.java"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L61-L84"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "e09f2a23674fd73296dd4d1fabf1a2c812bfe69ff02abc96a4be35af6a18e512"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6786
		version = 4

	strings:
		$fn1 = "runCmd" wide ascii fullword
		$fn2 = "RealCMD" ascii wide fullword
		$fn3 = "buildJson" ascii wide fullword

	condition:
		all of ( $fn* )
}
rule VOLEXITY_Apt_Malware_Win_Gimmick_Dotnet_Base : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detects the base version of GIMMICK written in .NET."
		author = "threatintel@volexity.com"
		id = "be42d85f-3143-51d3-b148-95d0ae666771"
		date = "2020-03-16"
		modified = "2024-08-19"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-03-22 GIMMICK/indicators/yara.yar#L60-L86"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "39a38ea189d5e840f9334cb7ec8f390444139b39c6f426906a8845f9a1ada9f7"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "b554bfe4c2da7d0ac42d1b4f28f4aae854331fd6d2b3af22af961f6919740234"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6628
		version = 3

	strings:
		$other1 = "srcStr is null" wide
		$other2 = "srcBs is null " wide
		$other3 = "Key cannot be null" wide
		$other4 = "Faild to get target constructor, targetType=" wide
		$other5 = "hexMoudule(public key) cannot be null or empty." wide
		$other6 = "https://oauth2.googleapis.com/token" wide

	condition:
		5 of ( $other* )
}
rule VOLEXITY_Webshell_Java_Behinder_Shellservice : FILE MEMORY {
    meta:
		description = "Looks for artifacts generated (generally seen in .class files) related to the Behinder webshell."
		author = "threatintel@volexity.com"
		id = "21c1e3e9-d048-5c60-9c21-8e54b27f359a"
		date = "2022-03-18"
		modified = "2024-07-30"
		reference = "https://github.com/MountCloud/BehinderClientSource/blob/master/src/main/java/net/rebeyond/behinder/core/ShellService.java"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L1-L29"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "373a8d4ef81e9bbbf1f24ebf0389e7da4b73f88786cc8e1d286ccc9f4c36debc"
		score = 75
		quality = 30
		tags = "FILE, MEMORY"
		hash1 = "9a9882f9082a506ed0fc4ddaedd50570c5762deadcaf789ac81ecdbb8cf6eff2"
		os = "win,linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6615
		version = 3

	strings:
		$s1 = "CONNECT" ascii fullword
		$s2 = "DISCONNECT" ascii fullword
		$s3 = "socket_" ascii fullword
		$s4 = "targetIP" ascii fullword
		$s5 = "targetPort" ascii fullword
		$s6 = "socketHash" ascii fullword
		$s7 = "extraData" ascii fullword

	condition:
		all of them
}
rule VOLEXITY_Malware_Golang_Pantegana : FILE MEMORY {
    meta:
		description = "Detects PANTEGANA, a Golang backdoor used by a range of threat actors due to its public availability."
		author = "threatintel@volexity.com"
		id = "b6154165-68e0-5986-a0cf-5631d369c230"
		date = "2022-03-30"
		modified = "2025-03-21"
		reference = "https://github.com/elleven11/pantegana"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L89-L119"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "791a664a6b4b98051cbfacb451099de085cbab74d73771709377ab68a5a23d2b"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "8297c99391aae918f154077c61ea94a99c7a339166e7981d9912b7fdc2e0d4f0"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6631
		version = 3

	strings:
		$s1 = "RunFingerprinter" ascii
		$s2 = "SendSysInfo" ascii
		$s3 = "ExecAndGetOutput" ascii
		$s4 = "RequestCommand" ascii
		$s5 = "bindataRead" ascii
		$s6 = "RunClient" ascii
		$magic = "github.com/elleven11/pantegana" ascii

	condition:
		5 of ( $s* ) or $magic
}
rule VOLEXITY_Malware_Any_Pupyrat_B : FILE MEMORY {
    meta:
		description = "Detects the PUPYRAT malware family, a cross-platform RAT written in Python."
		author = "threatintel@volexity.com"
		id = "ec8d0448-f47d-5c6e-bcf9-8f40ae83a96f"
		date = "2022-04-07"
		modified = "2025-03-21"
		reference = "https://github.com/n1nj4sec/pupy"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L120-L157"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "f5b5f35ee783ff1163072591c6d48a85894729156935650a0fd166ae22a2ea00"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "7474a6008b99e45686678f216af7d6357bb70a054c6d9b05e1817c8d80d536b4"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6689
		version = 4

	strings:
		$elf1 = "LD_PRELOAD=%s HOOK_EXIT=%d CLEANUP=%d exec %s 1>/dev/null 2>/dev/null" ascii
		$elf2 = "reflective_inject_dll" fullword ascii
		$elf3 = "ld_preload_inject_dll" fullword ascii
		$pupy1 = "_pupy.error" ascii
		$pupy2 = "pupy://" ascii
		$s1 = "Args not passed" ascii
		$s2 = "Too many args" ascii
		$s3 = "Can't execute" ascii
		$s4 = "mexec:stdin" ascii
		$s5 = "mexec:stdout" ascii
		$s6 = "mexec:stderr" ascii
		$s7 = "LZMA error" ascii

	condition:
		any of ( $elf* ) or all of ( $pupy* ) or all of ( $s* )
}
rule VOLEXITY_Webshell_Jsp_Godzilla : FILE MEMORY {
    meta:
		description = "Detects the JSP implementation of the Godzilla Webshell."
		author = "threatintel@volexity.com"
		id = "47c8eab8-84d7-5566-b757-5a6dcc7579b7"
		date = "2021-11-08"
		modified = "2024-07-30"
		reference = "https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L1-L34"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "52cba9545f662da18ca6e07340d7a9be637b89e7ed702dd58cac545c702a00e3"
		score = 75
		quality = 55
		tags = "FILE, MEMORY"
		hash1 = "2786d2dc738529a34ecde10ffeda69b7f40762bf13e7771451f13a24ab7fc5fe"
		os = "win,linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6100
		version = 6

	strings:
		$s1 = ".getWriter().write(base64Encode(" wide ascii
		$s2 = ".getAttribute(" ascii wide
		$s3 = "java.security.MessageDigest" ascii wide
		$auth1 = /String xc=\"[a-f0-9]{16}\"/ ascii wide
		$auth2 = "String pass=\"" ascii wide
		$magic = "class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q"
		$magic2 = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class"

	condition:
		all of ( $s* ) or all of ( $auth* ) or any of ( $magic* )
}
rule VOLEXITY_Susp_Jsp_General_Runtime_Exec_Req : FILE MEMORY {
    meta:
		description = "Looks for a common design pattern in webshells where a request attribute is passed as an argument to exec()."
		author = "threatintel@volexity.com"
		id = "7f1539bd-a2f0-50dd-b500-ada4e0971d13"
		date = "2022-02-02"
		modified = "2024-07-30"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L35-L56"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "d3048aba80c1c39f1673931cd2d7c5ed83045603b0ad204073fd788d0103a6c8"
		score = 65
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "4935f0c50057e28efa7376c734a4c66018f8d20157b6584399146b6c79a6de15"
		os = "win,linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6450
		version = 3

	strings:
		$s1 = "Runtime.getRuntime().exec(request." ascii

	condition:
		$s1
}
rule VOLEXITY_Webshell_Jsp_Regeorg : FILE MEMORY {
    meta:
		description = "Detects the reGeorg webshells' JSP version."
		author = "threatintel@volexity.com"
		id = "205ee383-4298-5469-a509-4ce3eaf9dd0e"
		date = "2022-03-08"
		modified = "2024-09-20"
		reference = "https://github.com/SecWiki/WebShell-2/blob/master/reGeorg-master/tunnel.jsp"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L57-L86"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "cecb71605d9112d509823c26e40e1cf9cd6db581db448db5c9ffc63a2bfe529e"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "f9b20324f4239a8c82042d8207e35776d6777b6305974964cd9ccc09d431b845"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6575
		version = 5

	strings:
		$magic = "socketChannel.connect(new InetSocketAddress(target, port))" ascii
		$a1 = ".connect(new InetSocketAddress" ascii
		$a2 = ".configureBlocking(false)" ascii
		$a3 = ".setHeader(" ascii
		$a4 = ".getHeader(" ascii
		$a5 = ".flip();" ascii

	condition:
		$magic or all of ( $a* )
}
rule VOLEXITY_Apt_Malware_Win_Applejeus_Oct22 : LAZYPINE FILE MEMORY {
    meta:
		description = "Detects AppleJeus DLL samples."
		author = "threatintel@volexity.com"
		id = "f88e2253-e296-57d8-a627-6cb4ccff7a92"
		date = "2022-11-03"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L1-L22"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "46f3325a7e8e33896862b1971f561f4871670842aecd46bcc7a5a1af869ecdc4"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "82e67114d632795edf29ce1d50a4c1c444846d9e16cd121ce26e63c8dc4a1629"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8495
		version = 3

	strings:
		$s1 = "HijackingLib.dll" ascii

	condition:
		$s1
}
rule VOLEXITY_Apt_Malware_Win_Applejeus_B_Oct22 : LAZYPINE FILE MEMORY {
    meta:
		description = "Detects unpacked AppleJeus samples."
		author = "threatintel@volexity.com"
		id = "8586dc64-225b-5f28-a6d6-b9b6e8f1c815"
		date = "2022-11-03"
		modified = "2025-05-21"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L24-L54"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "76f3c9692ea96d3cadbbcad03477ab6c53445935352cb215152b9b5483666d43"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "9352625b3e6a3c998e328e11ad43efb5602fe669aed9c9388af5f55fadfedc78"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8497
		version = 5

	strings:
		$key1 = "AppX7y4nbzq37zn4ks9k7amqjywdat7d"
		$key2 = "Gd2n5frvG2eZ1KOe"
		$str1 = "Windows %d(%d)-%s"
		$str2 = "&act=check"

	condition:
		( any of ( $key* ) and 1 of ( $str* ) ) or all of ( $str* )
}
rule VOLEXITY_Apt_Malware_Win_Applejeus_C_Oct22 : LAZYPINE MEMORY {
    meta:
		description = "Detects unpacked AppleJeus samples."
		author = "threatintel@volexity.com"
		id = "c9cbddde-220c-5e26-8760-85c29b98bfeb"
		date = "2022-11-03"
		modified = "2023-09-28"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L57-L84"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "a9e635d9353c8e5c4992beba79299fb889a7a3d5bc3eaf191f8bb7f51258a6c6"
		score = 75
		quality = 80
		tags = "LAZYPINE, MEMORY"
		hash1 = "a0db8f8f13a27df1eacbc01505f311f6b14cf9b84fbc7e84cb764a13f001dbbb"
		os = "win"
		os_arch = "all"
		scan_context = "memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8519
		version = 3

	strings:
		$str1 = "%sd.e%sc \"%s > %s 2>&1\"" wide
		$str2 = "tuid"
		$str4 = "payload"
		$str5 = "fconn"
		$str6 = "Mozilla_%lu"

	condition:
		5 of ( $str* )
}
rule VOLEXITY_Apt_Malware_Win_Applejeus_D_Oct22 : LAZYPINE FILE MEMORY {
    meta:
		description = "Detected AppleJeus unpacked samples."
		author = "threatintel@volexity.com"
		id = "80d2821b-a437-573e-9e9d-bf79f9422cc9"
		date = "2022-11-10"
		modified = "2025-05-21"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L87-L112"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "23c0642e5be15a75a39d089cd52f2f14d633f7af6889140b9ec6e53c5c023974"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "a241b6611afba8bb1de69044115483adb74f66ab4a80f7423e13c652422cb379"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8534
		version = 3

	strings:
		$reg = "Software\\Bitcoin\\Bitcoin-Qt"
		$pattern = "%s=%d&%s=%s&%s=%s&%s=%d"
		$exec = " \"%s\", RaitingSetupUI "
		$http = "Accept: */*" wide

	condition:
		all of them
}
rule VOLEXITY_Apt_Malware_Js_Sharpext : SHARPPINE FILE MEMORY {
    meta:
		description = "A malicious Chrome browser extension used by the SharpPine threat actor to steal Gmail data from a victim."
		author = "threatintel@volexity.com"
		id = "61b5176a-ff73-5fce-bc70-c9e09bb5afed"
		date = "2021-09-14"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-07-28 SharpTongue SharpTongue Deploys Clever Mail-Stealing Browser Extension SHARPEXT/yara.yar#L1-L52"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "0ed58c8646582ee36aeac650fac02d1e4962d45c0f6a24783c021d9267bed192"
		score = 75
		quality = 80
		tags = "SHARPPINE, FILE, MEMORY"
		hash1 = "1c9664513fe226beb53268b58b11dacc35b80a12c50c22b76382304badf4eb00"
		hash2 = "6025c66c2eaae30c0349731beb8a95f8a5ba1180c5481e9a49d474f4e1bb76a4"
		hash3 = "6594b75939bcdab4253172f0fa9066c8aee2fa4911bd5a03421aeb7edcd9c90c"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5916
		version = 5

	strings:
		$s1 = "\"mode=attach&name=\"" ascii
		$s2 = "\"mode=new&mid=\"" ascii
		$s3 = "\"mode=attlist\"" ascii
		$s4 = "\"mode=list\"" ascii
		$s5 = "\"mode=domain\"" ascii
		$s6 = "\"mode=black\"" ascii
		$s7 = "\"mode=newD&d=\"" ascii
		$mark1 = "chrome.runtime.onMessage.addListener" ascii
		$mark2 = "chrome.webNavigation.onCompleted.addListener" ascii
		$enc1 = "function BSue(string){" ascii
		$enc2 = "function BSE(input){" ascii
		$enc3 = "function bin2hex(byteArray)" ascii
		$xhr1 = ".send(\"mode=cd1" ascii
		$xhr2 = ".send(\"mode=black" ascii
		$xhr3 = ".send(\"mode=domain" ascii
		$xhr4 = ".send(\"mode=list" ascii
		$manifest1 = "\"description\":\"advanced font\"," ascii
		$manifest2 = "\"scripts\":[\"bg.js\"]" ascii
		$manifest3 = "\"devtools_page\":\"dev.html\"" ascii

	condition:
		(5 of ( $s* ) and all of ( $mark* ) ) or all of ( $enc* ) or 3 of ( $xhr* ) or 2 of ( $manifest* )
}
rule VOLEXITY_Apt_Win_Powerstar_Memonly : CHARMINGKITTEN {
    meta:
		description = "Detects the initial stage of the memory only variant of PowerStar."
		author = "threatintel@volexity.com"
		id = "469fc433-da9e-55ed-99fb-9560ec86a179"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L20-L65"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "d790ff204e4e8adeb3e887d9ebce743e958b523c48317d017487b1b0c6aebc11"
		score = 75
		quality = 78
		tags = "CHARMINGKITTEN"
		hash1 = "977cf5cc1d0c61b7364edcf397e5c67d910fac628c6c9a41cf9c73b3720ce67f"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s_1 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($in.substring(3)))"
		$s_2 = "[Convert]::ToByte(([Convert]::ToString(-bnot ($text_bytes[$i])"
		$s_3 = "$Exec=[System.Text.Encoding]::UTF8.GetString($text_bytes)"
		$s_4 = "((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})"
		$f_1 = "function Gorjol{"
		$f_2 = "Borjol \"$"
		$f_3 = "Gorjol -text"
		$f_4 = "function Borjoly{"
		$f_6 = "$filename = $env:APPDATA+\"\\Microsoft\\Windows\\DocumentPreview.pdf\";"
		$f_7 = "$env:APPDATA+\"\\Microsoft\\Windows\\npv.txt\""
		$f_8 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\brt8ts74e.bat"
		$f_9 = "\\Microsoft\\Windows\\s7qe52.txt"
		$f_10 = "$yeolsoe2 = $yeolsoe"
		$f_11 = "setRequestHeader(\"Content-DPR\""
		$f_12 = "getResponseHeader(\"Content-DPR\")"
		$f_13 = {24 43 6f 6d 6d 61 6e 64 50 61 72 74 73 20 3d 24 53 65 73 73 69 6f 6e 52 65 73 70 6f 6e 73 65 2e 53 70 6c 69 74 28 22 b6 22 29}
		$f_14 = "$language -like \"*shar*\""
		$f_15 = "$language -like \"*owers*\""
		$alias_1 = "(gcm *v????E?P?e*)"
		$alias_2 = "&(gcm *ke-e*) $Command"
		$key = "T2r0y1M1e1n1o0w1"
		$args_1 = "$sem.Close()"
		$args_2 = "$cem.Close()"
		$args_3 = "$mem.Close()"
		$command_1 = "_____numone_____"
		$command_2 = "_____mac2_____"
		$command_3 = "_____yeolsoe_____"

	condition:
		2 of ( $s_* ) or any of ( $f_* ) or 2 of ( $alias_* ) or $key or all of ( $args_* ) or any of ( $command_* )
}
rule VOLEXITY_Apt_Win_Powerstar_Logmessage : CHARMINGKITTEN {
    meta:
		description = "Detects interesting log message embedded in memory only version of PowerStar."
		author = "threatintel@volexity.com"
		id = "5979c776-5138-50e2-adab-0793ad86ba76"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L66-L79"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "539c9a8b3de24f2c8058d204900344756a8031822ebebc312612b8fb8422e341"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s_1 = "wau, ije ulineun mueos-eul halkkayo?"

	condition:
		all of them
}
rule VOLEXITY_Apt_Malware_Win_Avburner : DEVIOUSBAMBOO FILE MEMORY {
    meta:
		description = "Detects AVBurner based on a combination of API calls used, hard-coded strings and bytecode patterns."
		author = "threatintel@volexity.com"
		id = "1bde0861-4820-5bb1-98a3-516092c91be0"
		date = "2023-01-02"
		modified = "2024-08-16"
		reference = "https://www.trendmicro.com/en_us/research/22/k/hack-the-real-box-apt41-new-subgroup-earth-longzhi.html"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-03-07 AVBurner/yara.yar#L1-L40"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "4b1b1a1293ccd2c0fd51075de9376ebb55ab64972da785153fcb0a4eb523a5eb"
		logic_hash = "56ff6c8a4b737959a1219699a0457de1f0c34fead4299033840fb23c56a0caad"
		score = 75
		quality = 80
		tags = "DEVIOUSBAMBOO, FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8780
		version = 4

	strings:
		$api1 = "PspCreateProcessNotifyRoutineAddress" wide
		$api2 = "PspCreateThreadNotifyRoutineAddress" wide
		$api3 = "PspLoadImageNotifyRoutineAddress" wide
		$str1 = "\\\\.\\RTCORE64" wide
		$str2 = "\\\\%ws/pipe/%ws" wide
		$str3 = "CreateServerW Failed %u" wide
		$str4 = "OpenSCManager Failed %u" wide
		$str5 = "Get patternAddress" wide
		$pattern1 = { 4C 8B F9 48 8D 0C C1 E8 }
		$pattern2 = { 48 8D 0C DD 00 00 00 00  45 33 C0 49 03 CD 48 8B }
		$pattern3 = { 48 8D 04 C1 48 89 45 70 48 8B C8 E8 }
		$pattern4 = { 49 8D 0C FC 45 33 C0 48 8B D6 E8 00 00 00 00 00}
		$pattern5 = { 45 33 C0 48 8D 0C D9 48 8B D7 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$pattern6 = { 41 0F BA 6D 00 0A BB 01 00 00 00 4C 8B F2 4C 8B F9 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		all of ( $api* ) or all of ( $str* ) or all of ( $pattern* )
}
rule VOLEXITY_Apt_Malware_Any_Reloadext_Plugin : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detection for RELOADEXT, a Google Chrome extension malware."
		author = "threatintel@volexity.com"
		id = "6c6c8bee-2a13-5645-89ef-779f00264fd9"
		date = "2024-02-23"
		modified = "2024-08-02"
		reference = "TIB-20240227"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L4-L36"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "2b11f8fc5b6260ebf00bde83585cd7469709a4979ca579cdf065724bc15052fc"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "9d0928b3cc21ee5e1f2868f692421165f46b5014a901636c2a2b32a4c500f761"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10282
		version = 4

	strings:
		$man1 = "Reload page with Internet Explorer compatible mode."
		$man2 = "\"http://*/*\""
		$code1 = ";chrome["
		$code2 = "XMLHttpRequest(),_"
		$code3 = "0x400*0x400"

	condition:
		all of ( $man* ) or ( #code1 > 8 and #code2 >= 2 and #code3 >= 2 )
}
rule VOLEXITY_Apt_Malware_Any_Macma_A : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detects variants of the MACMA backdoor, variants of MACMA have been discovered for macOS and android."
		author = "threatintel@volexity.com"
		id = "6ab45af1-41e5-53fc-9297-e2bc07ebf797"
		date = "2021-11-12"
		modified = "2024-08-02"
		reference = "https://blog.google/threat-analysis-group/analyzing-watering-hole-campaign-using-macos-exploits/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L63-L111"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "7ebaff9fddf6491d6b1ed9ab14c1b87dc8df850536e55aa723d625a593b33ed7"
		score = 75
		quality = 53
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"
		hash2 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
		hash3 = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
		hash4 = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
		os = "all"
		os_arch = "all"
		report1 = "TIB-20231221"
		report2 = "TIB-20240227"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6114
		version = 9

	strings:
		$magic1 = "curl -o %s http://cgi1.apnic.net/cgi-bin/my-ip.php" fullword ascii
		$magic2 = "[FST%d]: WhyUserCancel UNKNOW: %d" fullword ascii
		$magic3 = "[FST%d]: wait C2 prepare ready TIMEOUT, fd: %d" fullword ascii
		$magic4 = "[FST%d]: wait C2 ack file content TIMEOUT, fd: %d" fullword ascii
		$magic5 = "[FST%d]: TIMER_CHECK_CANCEL WhyUserCancel UNKNOW: %d" fullword ascii
		$magic6 = "[FST%d]: encrypt file info key=%s, crc v1=0x%p, v2=0x%p" fullword ascii
		$s1 = "auto bbbbbaaend:%d path %s" fullword ascii
		$s2 = "0keyboardRecirderStopv" fullword ascii
		$s3 = "curl begin..." fullword ascii
		$s4 = "curl over!" fullword ascii
		$s5 = "kAgent fail" fullword ascii
		$s6 = "put !!!!" fullword ascii
		$s7 = "vret!!!!!! %d" fullword ascii
		$s8 = "save Setting Success" fullword ascii
		$s9 = "Start Filesyste Search." fullword ascii
		$s10 = "./SearchFileTool" fullword ascii
		$s11 = "put unknow exception in MonitorQueue" fullword ascii
		$s12 = "./netcfg2.ini" fullword ascii
		$s13 = ".killchecker_" fullword ascii
		$s14 = "./param.ini" fullword ascii

	condition:
		any of ( $magic* ) or 7 of ( $s* )
}
rule VOLEXITY_Apt_Malware_Win_Pocostick_Jul23 : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detects the July 2023 POCOSTICK variant. These strings are only visible in memory after several rounds of shellcode decryption."
		author = "threatintel@volexity.com"
		id = "9632a7fc-06da-58b4-b95c-b46aeb9dd41d"
		date = "2023-07-24"
		modified = "2024-08-02"
		reference = "TIB-20231221"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L206-L235"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "19487db733c7f793be2a1287df32a165e46f6af0e940b13b389f4d675b5100c4"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "ec3e787c369ac4b28447e7cacc44d70a595e39d47f842bacb07d19b12cab6aad"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9542
		version = 3

	strings:
		$str1 = "Folder PATH listing form volume" wide
		$str2 = "Volume serial number is 0000-1111" wide
		$str3 = "Type:Error" wide
		$str4 = "Type:Desktop" wide
		$str5 = "Type:Laptop" wide
		$str6 = "Type:Vitual" wide
		$str7 = ".unicode.tmp" wide
		$str8 = "EveryOne" wide

	condition:
		6 of them
}
rule VOLEXITY_Apt_Malware_Py_Dustpan_Pyloader : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detects Python script used by KPlayer to update, modified by attackers to download a malicious payload."
		author = "threatintel@volexity.com"
		id = "446d2eef-c60a-50ed-9ff1-df86b6210dff"
		date = "2023-07-21"
		modified = "2024-08-02"
		reference = "TIB-20231221"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L236-L270"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "bb3a70dad28181534e27abbbd618165652c137264bfd3726ae4480c642493a3b"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9530
		version = 4

	strings:
		$s_1 = "def count_md5(src)"
		$s_2 = "urllib.request.urlretrieve(image_url,main)"
		$s_3 = "m1 != '4c8a326899272d2fe30e818181f6f67f'"
		$s_4 = "os.path.split(os.path.realpath(__file__))[0]"
		$s_5 = "r_v = os.system('curl '+ini_url+cc)"
		$s_6 = "b41ef5f591226a0d5adce99cb2e629d8"
		$s_7 = "1df495e7c85e59ad0de1b9e50912f8d0"
		$s_8 = "tasklist | findstr mediainfo.exe"
		$url_1 = "http://dl1.5kplayer.com/youtube/youtube_dl.png"
		$url_2 = "http://dl1.5kplayer.com/youtube/youtube.ini?fire="
		$path_1 = "C:\\\\ProgramData\\\\Digiarty\\\\mediainfo.exe"

	condition:
		3 of ( $s_* ) or any of ( $url_* ) or $path_1
}
rule VOLEXITY_Apt_Malware_Vbs_Basicstar_A : CHARMINGCYPRESS FILE MEMORY {
    meta:
		description = "VBS backdoor which bares architectural similarity to the POWERSTAR malware family."
		author = "threatintel@volexity.com"
		id = "e790defe-2bd5-5629-8420-ce8091483589"
		date = "2024-01-04"
		modified = "2025-05-21"
		reference = "TIB-20240111"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L68-L98"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "977bb42553bb6585c8d0e1e89675644720ca9abf294eccd797e20d4bca516810"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "c6f91e5585c2cbbb8d06b7f239e30b271f04393df4fb81815f6556fa4c793bb0"
		os = "win"
		os_arch = "all"
		report2 = "TIB-20240126"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10037
		version = 8

	strings:
		$s1 = "Base64Encode(EncSess)" ascii wide
		$s2 = "StrReverse(PlainSess)" ascii wide
		$s3 = "ComDecode, \"Module\"" ascii wide
		$s4 = "ComDecode, \"SetNewConfig\"" ascii wide
		$s5 = "ComDecode, \"kill\"" ascii wide
		$magic = "cmd /C start /MIN curl --ssl-no-revoke -s -d " ascii wide

	condition:
		3 of ( $s* ) or $magic
}
rule VOLEXITY_Apt_Malware_Ps1_Powerless_B : CHARMINGCYPRESS FILE MEMORY {
    meta:
		description = "Detects POWERLESS malware."
		author = "threatintel@volexity.com"
		id = "e62703b5-32fb-5ceb-9f21-f52a4871f3d9"
		date = "2023-10-25"
		modified = "2024-01-29"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L99-L156"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "eb9d199c1f7c2a42d711c1a44ab13526787169c18a77ce988568525baca043ef"
		score = 75
		quality = 78
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "62de7abb39cf4c47ff120c7d765749696a03f4fa4e3e84c08712bb0484306ae1"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9794
		version = 5

	strings:
		$fun_1 = "function verifyClickStorke"
		$fun_2 = "function ConvertTo-SHA256"
		$fun_3 = "function Convert-Tobase" fullword
		$fun_4 = "function Convert-Frombase" fullword
		$fun_5 = "function Send-Httppacket"
		$fun_6 = "function Generat-FetchCommand"
		$fun_7 = "function Create-Fetchkey"
		$fun_8 = "function Run-Uploader"
		$fun_9 = "function Run-Shot" fullword
		$fun_10 = "function ShotThis("
		$fun_11 = "function File-Manager"
		$fun_12 = "function zip-files"
		$fun_13 = "function Run-Stealer"
		$fun_14 = "function Run-Downloader"
		$fun_15 = "function Run-Stro" fullword
		$fun_16 = "function Run-Tele" fullword
		$fun_17 = "function Run-Voice"
		$s_1 = "if($commandtype -eq \"klg\")"
		$s_2 = "$desrilizedrecievedcommand"
		$s_3 = "$getAsyncKeyProto = @"
		$s_4 = "$Global:BotId ="
		$s_5 = "$targetCLSID = (Get-ScheduledTask | Where-Object TaskName -eq"
		$s_6 = "$burl = \"$Global:HostAddress/"
		$s_7 = "$hashString = [System.BitConverter]::ToString($hash).Replace('-','').ToLower()"
		$s_8 = "$Global:UID = ((gwmi win32_computersystemproduct).uuid -replace '[^0-9a-z]').substring("
		$s_9 = "$rawpacket = \"{`\"MId`\":`\"$Global:MachineID`\",`\"BotId`\":`\"$basebotid`\"}\""
		$s_12 = "Runned Without any Error"
		$s_13 = "$commandresponse = (Invoke-Expression $instruction -ErrorAction Stop) | Out-String"
		$s_14 = "Operation started successfuly"
		$s_15 = "$t_path = (Get-WmiObject Win32_Process -Filter \"name = '$process'\" | Select-Object CommandLine).CommandLine"
		$s_16 = "?{ $_.DisplayName -match \"Telegram Desktop\" } | %{$app_path += $_.InstallLocation }"
		$s_17 = "$chlids = get-ChildItem $t -Recurse -Exclude \"$t\\tdata\\user_data\""
		$s_18 = "if($FirsttimeFlag -eq $True)"
		$s_19 = "Update-Conf -interval $inter -url $url -next_url $next -conf_path $conf_path -key $config_key"

	condition:
		3 of ( $fun_* ) or any of ( $s_* )
}
rule VOLEXITY_Apt_Malware_Ps1_Powerstar_Generic : CHARMINGCYPRESS FILE MEMORY {
    meta:
		description = "Detects POWERSTAR modules based on common HTTP functions used across modules."
		author = "threatintel@volexity.com"
		id = "71a3e99d-e1c8-5ac1-abbc-2ba5cba80799"
		date = "2023-06-02"
		modified = "2024-01-26"
		reference = "TIB-20240126"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L323-L351"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "4da02190ffd16304eccbc0d12dfcc5637a6b785af0e3dc3dfcafcfe114597eb2"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9356
		version = 3

	strings:
		$http1 = "Send_Upload" ascii wide
		$http2 = "Send_Post_Data" ascii wide
		$json1 = "{\"OS\":\"" ascii wide
		$json2 = "{\"ComputerName\":\"' + $env:COMPUTERNAME + '\"}" ascii wide
		$json3 = "{\"Token\"" ascii wide
		$json4 = "{\"num\":\"" ascii wide

	condition:
		all of ( $http* ) or all of ( $json* )
}
rule VOLEXITY_Apt_Malware_Win_Deepdata_Module : BRAZENBAMBOO FILE MEMORY {
    meta:
		description = "Detects modules used by DEEPDATA based on the required export names used by those modules."
		author = "threatintel@volexity.com"
		id = "1287f5dd-9229-57ce-a91a-73d61041df80"
		date = "2024-07-30"
		modified = "2024-11-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-11-15 BrazenBamboo/rules.yar#L1-L25"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "d36f34343826daf7f7368118c7127c7181a54c99a01803016c9a6965abb309cb"
		score = 75
		quality = 80
		tags = "BRAZENBAMBOO, FILE, MEMORY"
		hash1 = "c782346bf9e5c08a0c43a85d4991f26b0b3c99c054fa83beb4a9e406906f011e"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10868
		version = 2

	strings:
		$str1 = "ExecuteCommand"
		$str2 = "GetPluginCommandID"
		$str3 = "GetPluginName"
		$str4 = "GetPluginVersion"

	condition:
		all of them
}
rule VOLEXITY_Apt_Malware_Win_Lightspy_Orchestrator_Decoded_Core : BRAZENBAMBOO FILE MEMORY {
    meta:
		description = "Detects the decoded orchestrator for the Windows variant of the LightSpy malware family. This file is normally stored in an encoded state on the C2 server and is used as the core component of this malware family, loading additional plugins from the C2 whilst managing all the C2 communication etc."
		author = "threatintel@volexity.com"
		id = "44f8d7a4-7f48-5960-91a7-baf475f7d291"
		date = "2024-02-15"
		modified = "2024-07-03"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-11-15 BrazenBamboo/rules.yar#L244-L287"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "f0189c0a84c53e365130e9683f2f2b2f73c14412d8e4d0251a4780d0e80162d8"
		score = 75
		quality = 78
		tags = "BRAZENBAMBOO, FILE, MEMORY"
		hash1 = "80c0cdb1db961c76de7e4efb6aced8a52cd0e34178660ef34c128be5f0d587df"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10246
		version = 2

	strings:
		$s1 = "Enter RunWork......."
		$s2 = "it's running......."
		$s3 = "select ret = socket_error."
		$s4 = "%s\\\\account.bin"
		$s5 = "[CtrlLink]: get machine sn err:%d"
		$s6 = "wmic path Win32_VideoController get CurrentHorizontalResolution,CurrentVerticalResolution /format:list | findstr /v \\\"^$\\\""
		$s7 = "wmic csproduct get vendor,version /format:list | findstr /v \\\"^$\\\""
		$s8 = "local ip get sockname error=%d"
		$s9 = "connect goole dns error=%d"
		$s10 = "%s/api/terminal/upsert/"
		$s11 = "/963852741/windows/plugin/manifest"
		$s12 = "Hello deepdata."
		$s13 = "Start Light."
		$s14 = "InitialPluginManager Error."
		$s15 = "InitialCommandExe Error."
		$s16 = "ws open, and send logon info."
		$s17 = "plugin_replay_handler"
		$s18 = "light_x86.dll"
		$pdb1 = "\\light\\bin\\light_x86.pdb"
		$pdb2 = "\\light\\bin\\plugin"
		$pdb3 = "D:\\tmpWork\\"

	condition:
		1 of ( $pdb* ) or 5 of ( $s* )
}
rule VOLEXITY_Apt_Malware_Win_Lightspy_Orchestrator_Decoded_C2_Strings : BRAZENBAMBOO FILE MEMORY {
    meta:
		description = "Detects the decoded orchestrator for the Windows variant of the LightSpy malware family. This file is normally stored in an encoded state on the C2 server and is used as the core component of this malware family, loading additional plugins from the C2 whilst managing all the C2 communication etc."
		author = "threatintel@volexity.com"
		id = "a0af8fb7-13a3-54e8-8569-e8622fa80d89"
		date = "2024-02-15"
		modified = "2024-11-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-11-15 BrazenBamboo/rules.yar#L288-L337"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "eeaaf6e16d4854a2279bd62596f75cb8b8ec1b05f3b050f5dac97254704b9005"
		score = 75
		quality = 78
		tags = "BRAZENBAMBOO, FILE, MEMORY"
		hash1 = "80c0cdb1db961c76de7e4efb6aced8a52cd0e34178660ef34c128be5f0d587df"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10245
		version = 4

	strings:
		$s1 = "[WsClient][Error]:"
		$s2 = "[WsClient][Info]:"
		$s3 = "[WsClient]:WsClient"
		$s4 = "[WsClient][Info]:Ws"
		$s5 = "WsClient Worker Thread ID=%d"
		$s6 = "[LightWebClient]:"
		$s7 = "LightHttpGet err:%s"
		$s8 = "User-Agent: Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.145 Safari/537.36"
		$s9 = "KvList Err:%s"
		$s10 = "dataMultiPart malloc err:%d"
		$ctrl1 = "CTRL_HEART_BEAT"
		$ctrl2 = "CTRL_NET_CONFIG"
		$ctrl3 = "CTRL_COMMAND_PLAN"
		$ctrl4 = "CTRL_MODIFY_NET_CONFIG"
		$ctrl5 = "CTRL_UPLOAD_PLUGIN_STATUS"
		$ctrl6 = "CTRL_PLUGIN_EXECUTE_COMMAND"
		$ctrl7 = "CTRL_PLUGIN_COMMAND_STATUS"
		$ctrl8 = "CTRL_PLUGIN_STOP_COMMAND"
		$ctrl9 = "CTRL_GET_SLEEP_CONFIG"
		$ctrl10 = "CTRL_MODIFY_SLEEP_CONFIG"
		$ctrl11 = "CTRL_SLEEP_STATUS"
		$ctrl12 = "CTRL_UPDATE_PLUGIN"
		$ctrl13 = "CTRL_DESTROY"
		$ctrl14 = "CTRL_RECONFIG_REBOUNT_ADDRESS"
		$ctrl15 = "CTRL_AUTO_UPLOUD_FILE_CONFIG"
		$ctrl16 = "CTRL_UPLOUD_DEVICE_INFO"
		$ctrl17 = "CTRL_TEST_VPDN_ACCOUNT"

	condition:
		3 of ( $s* ) or 5 of ( $ctrl* )
}
rule VOLEXITY_Malware_Golang_Discordc2_Bmdyy_1 : FILE MEMORY {
    meta:
		description = "Detects a opensource malware available on github using strings in the binary. The DISGOMOJI malware family used by TransparentJasmine is based on this malware."
		author = "threatintel@volexity.com"
		id = "6816d264-4311-5e90-948b-2e27cdf0b720"
		date = "2024-03-28"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L216-L243"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "22b3e5109d0738552fbc310344b2651ab3297e324bc883d5332c1e8a7a1df29b"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "de32e96d1f151cc787841c12fad88d0a2276a93d202fc19f93631462512fffaf"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10390
		version = 3

	strings:
		$s1 = "File is bigger than 8MB" wide ascii
		$s2 = "Uploaded file to" wide ascii
		$s3 = "sess-%d" wide ascii
		$s4 = "Session *%s* opened" wide ascii
		$s5 = "%s%d_%dx%d.png" wide ascii

	condition:
		4 of them
}
rule VOLEXITY_Malware_Golang_Discordc2_Bmdyy : FILE MEMORY {
    meta:
		description = "Detects a opensource malware available on github using strings in the binary. DISGOMOJI used by TransparentJasmine is based on this malware."
		author = "threatintel@volexity.com"
		id = "1ddbf476-ba2d-5cbb-ad95-38e0ae8db71b"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "https://github.com/bmdyy/discord-c2"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L244-L267"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "38b860a43b9937351f74b01983888f18ad101cbe66560feb7455d46b713eba0f"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10264
		version = 12

	strings:
		$s1 = "**IP**: %s\n**User**: %s\n**Hostname**: %s\n**OS**: %s\n**CWD**" wide ascii

	condition:
		$s1
}
rule VOLEXITY_Apt_Webshell_Pl_Complyshell : UTA0178 FILE MEMORY {
    meta:
		description = "Detection for the COMPLYSHELL webshell."
		author = "threatintel@volexity.com"
		id = "6b44b5bc-a75f-573c-b9c3-562b7874e408"
		date = "2023-12-13"
		modified = "2024-01-12"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L3-L25"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "ff46691f1add20cff30fe996e2fb199ce42408e86d5642a8a43c430f2245b1f5"
		score = 75
		quality = 80
		tags = "UTA0178, FILE, MEMORY"
		hash1 = "8bc8f4da98ee05c9d403d2cb76097818de0b524d90bea8ed846615e42cb031d2"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9995
		version = 4

	strings:
		$s = "eval{my $c=Crypt::RC4->new("

	condition:
		$s
}
rule VOLEXITY_Apt_Webshell_Aspx_Glasstoken : UTA0178 FILE MEMORY {
    meta:
		description = "Detection for a custom webshell seen on Exchange server. The webshell contains two functions, the first is to act as a Tunnel, using code borrowed from reGeorg, the second is custom code to execute arbitrary .NET code."
		author = "threatintel@volexity.com"
		id = "2f07748a-a52f-5ac7-9d3e-50fd3ecea271"
		date = "2023-12-12"
		modified = "2024-09-30"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L26-L52"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "6b8183ac1e87a86c58760db51f767ed278cc0c838ed89e7435af7d0373e58b26"
		score = 75
		quality = 30
		tags = "UTA0178, FILE, MEMORY"
		hash1 = "26cbb54b1feb75fe008e36285334d747428f80aacdb57badf294e597f3e9430d"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9994
		version = 6

	strings:
		$s1 = "=Convert.FromBase64String(System.Text.Encoding.Default.GetString(" ascii
		$re = /Assembly\.Load\(errors\)\.CreateInstance\("[a-z0-9A-Z]{4,12}"\).GetHashCode\(\);/

	condition:
		for any i in ( 0 .. math.min ( #s1 , 100 ) ) : ( $re in ( @s1 [ i ] .. @s1 [ i ] + 512 ) )
}
rule VOLEXITY_Webshell_Aspx_Regeorg : FILE MEMORY {
    meta:
		description = "Detects the reGeorg webshell based on common strings in the webshell. May also detect other webshells which borrow code from ReGeorg."
		author = "threatintel@volexity.com"
		id = "02365a30-769e-5c47-8d36-a79608ffd121"
		date = "2018-08-29"
		modified = "2024-01-09"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L53-L86"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "9d901f1a494ffa98d967ee6ee30a46402c12a807ce425d5f51252eb69941d988"
		logic_hash = "4fed023e85a32052917f6db1e2e155c91586538938c03acc59f200a8264888ca"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 410
		version = 7

	strings:
		$a1 = "every office needs a tool like Georg" ascii
		$a2 = "cmd = Request.QueryString.Get(\"cmd\")" ascii
		$a3 = "exKak.Message" ascii
		$proxy1 = "if (rkey != \"Content-Length\" && rkey != \"Transfer-Encoding\")"
		$proxy_b1 = "StreamReader repBody = new StreamReader(response.GetResponseStream(), Encoding.GetEncoding(\"UTF-8\"));" ascii
		$proxy_b2 = "string rbody = repBody.ReadToEnd();" ascii
		$proxy_b3 = "Response.AddHeader(\"Content-Length\", rbody.Length.ToString());" ascii

	condition:
		any of ( $a* ) or $proxy1 or all of ( $proxy_b* )
}
rule VOLEXITY_Hacktool_Py_Pysoxy : FILE MEMORY {
    meta:
		description = "SOCKS5 proxy tool used to relay connections."
		author = "threatintel@volexity.com"
		id = "88094b55-784d-5245-9c40-b1eebf0e6e72"
		date = "2024-01-09"
		modified = "2024-01-09"
		reference = "TIB-20240109"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L87-L114"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "f73e9d3c2f64c013218469209f3b69fc868efafc151a7de979dde089bfdb24b2"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "e192932d834292478c9b1032543c53edfc2b252fdf7e27e4c438f4b249544eeb"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10065
		version = 3

	strings:
		$s1 = "proxy_loop" ascii
		$s2 = "connect_to_dst" ascii
		$s3 = "request_client" ascii
		$s4 = "subnegotiation_client" ascii
		$s5 = "bind_port" ascii

	condition:
		all of them
}
rule VOLEXITY_Apt_Malware_Py_Upstyle : UTA0218 FILE MEMORY {
    meta:
		description = "Detect the UPSTYLE webshell."
		author = "threatintel@volexity.com"
		id = "45726f35-8b3e-5095-b145-9e7f6da6838b"
		date = "2024-04-11"
		modified = "2024-04-12"
		reference = "TIB-20240412"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L1-L34"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "51923600b23d23f4ce29eac7f5ab9f7e1ddb45bed5f6727ddec4dcb75872e473"
		score = 75
		quality = 80
		tags = "UTA0218, FILE, MEMORY"
		hash1 = "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"
		hash2 = "0d59d7bddac6c22230187ef6cf7fa22bca93759edc6f9127c41dc28a2cea19d8"
		hash3 = "4dd4bd027f060f325bf6a90d01bfcf4e7751a3775ad0246beacc6eb2bad5ec6f"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10429
		version = 2

	strings:
		$stage1_str1 = "/opt/pancfg/mgmt/licenses/PA_VM"
		$stage1_str2 = "exec(base64."
		$stage2_str1 = "signal.signal(signal.SIGTERM,stop)"
		$stage2_str2 = "exec(base64."
		$stage3_str1 = "write(\"/*\"+output+\"*/\")"
		$stage3_str2 = "SHELL_PATTERN"

	condition:
		all of ( $stage1* ) or all of ( $stage2* ) or all of ( $stage3* )
}
rule VOLEXITY_Susp_Any_Jarischf_User_Path : FILE MEMORY {
    meta:
		description = "Detects paths embedded in samples in released projects written by Ferdinand Jarisch, a pentester in AISEC. These tools are sometimes used by attackers in real world intrusions."
		author = "threatintel@volexity.com"
		id = "062a6fdb-c516-5643-9c7c-deff32eeb95e"
		date = "2024-04-10"
		modified = "2024-04-15"
		reference = "TIB-20240412"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L59-L81"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "574d5b1fadb91c39251600e7d73d4993d4b16565bd1427a0e8d6ed4e7905ab54"
		score = 50
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10424
		version = 4

	strings:
		$proj_1 = "/home/jarischf/"

	condition:
		any of ( $proj_* )
}
rule VOLEXITY_Hacktool_Golang_Reversessh_Fahrj : FILE MEMORY {
    meta:
		description = "Detects a reverse SSH utility available on GitHub. Attackers may use this tool or similar tools in post-exploitation activity."
		author = "threatintel@volexity.com"
		id = "332e323f-cb16-5aa2-8b66-f3d6d50d94f2"
		date = "2024-04-10"
		modified = "2024-04-12"
		reference = "TIB-20240412"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L82-L116"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "38b40cc7fc1e601da2c7a825f1c2eff209093875a5829ddd2f4c5ad438d660f8"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10423
		version = 5

	strings:
		$fun_1 = "createLocalPortForwardingCallback"
		$fun_2 = "createReversePortForwardingCallback"
		$fun_3 = "createPasswordHandler"
		$fun_4 = "createPublicKeyHandler"
		$fun_5 = "createSFTPHandler"
		$fun_6 = "dialHomeAndListen"
		$fun_7 = "createExtraInfoHandler"
		$fun_8 = "createSSHSessionHandler"
		$fun_9 = "createReversePortForwardingCallback"
		$proj_1 = "github.com/Fahrj/reverse-ssh"

	condition:
		any of ( $proj_* ) or 4 of ( $fun_* )
}
rule VOLEXITY_Malware_Win_Backwash_Cpp : WHEELEDASH FILE MEMORY {
    meta:
		description = "CPP loader for the Backwash malware."
		author = "threatintel@volexity.com"
		id = "8a1c4ff1-1827-5e6f-b838-664d8c3be840"
		date = "2021-11-17"
		modified = "2023-11-13"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L3-L26"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "c8ed2d3103aa85363acd7f5573aeb936a5ab5a3bacbcf1f04e6b298299f24dae"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		hash1 = "0cf93de64aa4dba6cec99aa5989fc9c5049bc46ca5f3cb327b49d62f3646a852"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6147
		version = 2

	strings:
		$s1 = "cor1dbg.dll" wide
		$s2 = "XEReverseShell.exe" wide
		$s3 = "XOJUMAN=" wide

	condition:
		2 of them
}
rule VOLEXITY_Malware_Win_Iis_Shellsave : WHEELEDASH FILE MEMORY {
    meta:
		description = "Detects an AutoIT backdoor designed to run on IIS servers and to install a webshell."
		author = "threatintel@volexity.com"
		id = "a89defa5-4b22-5650-a0c0-f4b3cf3377a7"
		date = "2021-11-17"
		modified = "2023-08-17"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L27-L49"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "f34d6f4ecaa4cde5965f6b0deac55c7133a2be96f5c466f34775be6e7f730493"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		hash1 = "21683e02e11c166d0cf616ff9a1a4405598db7f4adfc87b205082ae94f83c742"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6146
		version = 4

	strings:
		$s1 = "getdownloadshell" ascii
		$s2 = "deleteisme" ascii
		$s3 = "sitepapplication" ascii
		$s4 = "getapplicationpool" ascii

	condition:
		all of them
}
rule VOLEXITY_Malware_Win_Backwash_Iis_Scout : WHEELEDASH FILE MEMORY {
    meta:
		description = "Simple backdoor which collects information about the IIS server it is installed on. It appears to the attacker refers to this components as 'XValidate' - i.e. to validate infected machines."
		author = "threatintel@volexity.com"
		id = "1f768b39-21a0-574d-9043-5104540003f7"
		date = "2021-11-17"
		modified = "2023-08-17"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L50-L78"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "18c4e338905ff299d75534006037e63a8f9b191f062cc97b0592245518015f88"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		hash1 = "6f44a9c13459533a1f3e0b0e698820611a18113c851f763797090b8be64fd9d5"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6145
		version = 3

	strings:
		$s1 = "SOAPRequest" ascii
		$s2 = "requestServer" ascii
		$s3 = "getFiles" ascii
		$s4 = "APP_POOL_CONFIG" wide
		$s5 = "<virtualDirectory" wide
		$s6 = "stringinstr" ascii
		$s7 = "504f5354" wide
		$s8 = "XValidate" ascii
		$s9 = "XEReverseShell" ascii
		$s10 = "XERsvData" ascii

	condition:
		6 of them
}
rule VOLEXITY_Malware_Win_Backwash_Iis : WHEELEDASH FILE MEMORY {
    meta:
		description = "Variant of the BACKWASH malware family with IIS worm functionality."
		author = "threatintel@volexity.com"
		id = "08a86a58-32af-5c82-90d2-d6603dae8d63"
		date = "2020-09-04"
		modified = "2023-08-17"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L181-L208"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "98e39573a3d355d7fdf3439d9418fdbf4e42c2e03051b5313d5c84f3df485627"
		logic_hash = "95a7f9e0afb031b49cd0da66b5a887d26ad2e06cce625bc45739b4a80e96ce9c"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 231
		version = 6

	strings:
		$a1 = "GetShell" ascii
		$a2 = "smallShell" ascii
		$a3 = "createSmallShell" ascii
		$a4 = "getSites" ascii
		$a5 = "getFiles " ascii
		$b1 = "action=saveshell&domain=" ascii wide
		$b2 = "&shell=backsession.aspx" ascii wide

	condition:
		all of ( $a* ) or any of ( $b* )
}
rule VOLEXITY_Webshell_Aspx_Regeorgtunnel : FILE MEMORY {
    meta:
		description = "A variation of the reGeorgtunnel open-source webshell."
		author = "threatintel@volexity.com"
		id = "b8aa27c9-a28a-5051-8f81-1184f28842ed"
		date = "2021-03-02"
		modified = "2024-10-18"
		reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-03-02 - Operation Exchange Marauder/indicators/yara.yar#L26-L56"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
		logic_hash = "ea3d0532cb609682922469e8272dc8061efca3b3ae27df738ef2646e30404c6f"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 4979
		version = 4

	strings:
		$s1 = "System.Net.Sockets"
		$s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"
		$t1 = ".Split('|')"
		$t2 = "Request.Headers.Get"
		$t3 = ".Substring("
		$t4 = "new Socket("
		$t5 = "IPAddress ip;"

	condition:
		all of ( $s* ) or all of ( $t* )
}
rule VOLEXITY_Apt_Webshell_Aspx_Sportsball : FILE MEMORY {
    meta:
		description = "The SPORTSBALL webshell, observed in targeted Microsoft Exchange attacks."
		author = "threatintel@volexity.com"
		id = "25b23a4c-8fc7-5d6f-b4b5-46fe2c1546d8"
		date = "2021-03-01"
		modified = "2024-07-30"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-03-02 - Operation Exchange Marauder/indicators/yara.yar#L57-L88"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
		logic_hash = "5ec5e52922e97a3080d397b69b2f42f09daa995271e218ea085fa2ec4e3abad2"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 4968
		version = 5

	strings:
		$uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
		$uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="
		$s1 = "Result.InnerText = string.Empty;"
		$s2 = "newcook.Expires = DateTime.Now.AddDays("
		$s3 = "System.Diagnostics.Process process = new System.Diagnostics.Process();"
		$s4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
		$s5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
		$s6 = "<input type=\"submit\" value=\"Upload\" />"

	condition:
		any of ( $uniq* ) or all of ( $s* )
}
rule VOLEXITY_Apt_Malware_Rb_Rokrat_Loader : INKYPINE FILE MEMORY {
    meta:
		description = "Ruby loader seen loading the ROKRAT malware family."
		author = "threatintel@volexity.com"
		id = "69d09560-a769-55d3-a442-e37f10453cde"
		date = "2021-06-22"
		modified = "2024-08-22"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L1-L32"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "30ae14fd55a3ab60e791064f69377f3b9de9b871adfd055f435df657f89f8007"
		score = 75
		quality = 55
		tags = "INKYPINE, FILE, MEMORY"
		hash1 = "5bc52f6c1c0d0131cee30b4f192ce738ad70bcb56e84180f464a5125d1a784b2"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5598
		version = 7

	strings:
		$magic1 = "'https://update.microsoft.com/driverupdate?id=" ascii wide
		$magic2 = "sVHZv1mCNYDO0AzI';" ascii wide
		$magic3 = "firoffset..scupd.size" ascii wide
		$magic4 = /alias UrlFilter[0-9]{2,5} eval;"/
		$s1 = "clRnbp9GU6oTZsRGZpZ"
		$s2 = "RmlkZGxlOjpQb2ludGVy"
		$s3 = "yVGdul2bQpjOlxGZklmR"
		$s4 = "XZ05WavBlO6UGbkRWaG"

	condition:
		any of ( $magic* ) or any of ( $s* )
}
rule VOLEXITY_Apt_Malware_Win_Decrok : INKYPINE FILE MEMORY {
    meta:
		description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
		author = "threatintel@volexity.com"
		id = "46be1793-6419-54fe-a78b-5d087e02626e"
		date = "2021-06-23"
		modified = "2023-09-28"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L62-L90"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
		logic_hash = "a551700943d5abc95af00fc4fefd416ace8d59037852c6bc5caf1d6bd09afd63"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE, MEMORY"
		os = "win"
		os_arch = "x86"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5606
		version = 4

	strings:
		$v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}
		$av1 = "Select * From AntiVirusProduct" wide
		$av2 = "root\\SecurityCenter2" wide
		$func1 = "CreateThread"
		$format = "%02x"

	condition:
		all of them and $func1 in ( @format .. @format + 10 )
}
rule VOLEXITY_Apt_Malware_Win_Dolphin : INKYPINE FILE MEMORY {
    meta:
		description = "North Korean origin malware which uses a custom Google App for c2 communications."
		author = "threatintel@volexity.com"
		id = "27bb2b41-f77d-5b95-b555-206c39ed9e6c"
		date = "2021-06-21"
		modified = "2025-01-27"
		reference = "https://www.welivesecurity.com/2022/11/30/whos-swimming-south-korean-waters-meet-scarcrufts-dolphin/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-17 - InkySquid Part 1/indicators/yara.yar#L1-L77"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "785a92087efc816c88c6eed6363c432d8d45198fbd5cef84c04dabd36b6316a6"
		score = 75
		quality = 55
		tags = "INKYPINE, FILE, MEMORY"
		hash1 = "837eaf7b736583497afb8bbdb527f70577901eff04cc69d807983b233524bfed"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5593
		version = 10

	strings:
		$magic = "host_name: %ls, cookie_name: %s, cookie: %s, CT: %llu, ET: %llu, value: %s, path: %ls, secu: %d, http: %d, last: %llu, has: %d"
		$f1 = "%ls.INTEG.RAW" wide
		$f2 = "edb.chk" ascii
		$f3 = "edb.log" ascii
		$f4 = "edbres00001.jrs" ascii
		$f5 = "edbres00002.jrs" ascii
		$f6 = "edbtmp.log" ascii
		$f7 = "cheV01.dat" ascii
		$chrome1 = "Failed to get chrome cookie"
		$chrome2 = "mail.google.com, cookie_name: OSID"
		$chrome3 = ".google.com, cookie_name: SID,"
		$chrome4 = ".google.com, cookie_name: __Secure-3PSID,"
		$chrome5 = "Failed to get Edge cookie"
		$chrome6 = "google.com, cookie_name: SID,"
		$chrome7 = "google.com, cookie_name: __Secure-3PSID,"
		$chrome8 = "Failed to get New Edge cookie"
		$chrome9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
		$chrome10 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
		$chrome11 = "Cookie: SID=%s; OSID=%s; __Secure-3PSID=%s"
		$chrome12 = "https://mail.google.com"
		$chrome13 = "result.html"
		$chrome14 = "GM_ACTION_TOKEN"
		$chrome15 = "GM_ID_KEY="
		$chrome16 = "/mail/u/0/?ik=%s&at=%s&view=up&act=prefs"
		$chrome17 = "p_bx_ie=1"
		$chrome18 = "myaccount.google.com, cookie_name: OSID"
		$chrome19 = "Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3"
		$chrome20 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
		$chrome21 = "Cookie: SID=%s; OSID=%s; __Secure-3PSID=%s"
		$chrome22 = "https://myaccount.google.com"
		$chrome23 = "result.html"
		$chrome24 = "myaccount.google.com"
		$chrome25 = "/_/AccountSettingsUi/data/batchexecute"
		$chrome26 = "f.req=%5B%5B%5B%22BqLdsd%22%2C%22%5Btrue%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at="
		$chrome27 = "response.html"
		$msg1 = "https_status is %s"
		$msg2 = "Success to find GM_ACTION_TOKEN and GM_ID_KEY"
		$msg3 = "Failed to find GM_ACTION_TOKEN and GM_ID_KEY"
		$msg4 = "Failed HttpSendRequest to mail.google.com"
		$msg5 = "Success to enable imap"
		$msg6 = "Failed to enable imap"
		$msg7 = "Success to find SNlM0e"
		$msg8 = "Failed to find SNlM0e"
		$msg9 = "Failed HttpSendRequest to myaccount.google.com"
		$msg10 = "Success to enable thunder access"
		$msg11 = "Failed to enable thunder access"

	condition:
		$magic or ( all of ( $f* ) and 3 of ( $chrome* ) ) or 24 of ( $chrome* ) or 4 of ( $msg* )
}
rule VOLEXITY_Apt_Malware_Win_Bluelight : INKYPINE FILE MEMORY {
    meta:
		description = "The BLUELIGHT malware family. Leverages Microsoft OneDrive for network communications."
		author = "threatintel@volexity.com"
		id = "5bfdc74b-592e-5f3d-9fb8-bbbbd0f6f0f6"
		date = "2021-04-23"
		modified = "2025-02-18"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-17 - InkySquid Part 1/indicators/yara.yar#L78-L120"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "45490dfc793bb95f153c0194989b25e0b2641fa9b9f6763d5733eab6483ffead"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE, MEMORY"
		hash1 = "7c40019c1d4cef2ffdd1dd8f388aaba537440b1bffee41789c900122d075a86d"
		hash2 = "94b71ee0861cc7cfbbae53ad2e411a76f296fd5684edf6b25ebe79bf6a2a600a"
		hash3 = "485246b411ef5ea9e903397a5490d106946a8323aaf79e6041bdf94763a0c028"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5284
		version = 12

	strings:
		$pdb1 = "\\Development\\BACKDOOR\\ncov\\"
		$pdb2 = "Release\\bluelight.pdb" nocase ascii
		$pdb3 = "D:\\Development\\GOLD-BACKDOOR\\Release\\FirstBackdoor.pdb"
		$pdb4 = "GOLD-BACKDOOR\\Release\\"
		$msg0 = "https://ipinfo.io" fullword
		$msg1 = "country" fullword
		$msg5 = "\"UserName\":\"" fullword
		$msg7 = "\"ComName\":\"" fullword
		$msg8 = "\"OS\":\"" fullword
		$msg9 = "\"OnlineIP\":\"" fullword
		$msg10 = "\"LocalIP\":\"" fullword
		$msg11 = "\"Time\":\"" fullword
		$msg12 = "\"Compiled\":\"" fullword
		$msg13 = "\"Process Level\":\"" fullword
		$msg14 = "\"AntiVirus\":\"" fullword
		$msg15 = "\"VM\":\"" fullword

	condition:
		any of ( $pdb* ) or all of ( $msg* )
}
rule VOLEXITY_Apt_Malware_Win_Flipflop_Ldr : COZYLARCH FILE MEMORY {
    meta:
		description = "A loader for the CobaltStrike malware family, which ultimately takes the first and second bytes of an embedded file, and flips them prior to executing the resulting payload."
		author = "threatintel@volexity.com"
		id = "58696a6f-55a9-5212-9372-a539cc327e6b"
		date = "2021-05-25"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L3-L26"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
		logic_hash = "a79d2b0700ae14f7a2af23c8f7df3df3564402b1137478008ccabefea0f543ad"
		score = 75
		quality = 80
		tags = "COZYLARCH, FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5443
		version = 6

	strings:
		$s1 = "irnjadle"
		$s2 = "BADCFEHGJILKNMPORQTSVUXWZY"
		$s3 = "iMrcsofo taBesC yrtpgoarhpciP orived r1v0."

	condition:
		all of ( $s* )
}
rule VOLEXITY_Malware_Win_Cobaltstrike_D : FILE MEMORY {
    meta:
		description = "The CobaltStrike malware family, variant D."
		author = "threatintel@volexity.com"
		id = "89a2459b-314b-513e-bd1a-8c4239a30338"
		date = "2021-05-25"
		modified = "2024-11-22"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L27-L54"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "b041efb8ba2a88a3d172f480efa098d72eef13e42af6aa5fb838e6ccab500a7c"
		logic_hash = "751b6832f2952d369cb616b28ac009d7bfcc4d92bf2db36d87d69bc1e9fa6c75"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5445
		version = 5

	strings:
		$s1 = "%s (admin)" fullword
		$s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
		$s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
		$s4 = "%s as %s\\%s: %d" fullword
		$s5 = "%s&%s=%s" fullword
		$s6 = "rijndael" fullword
		$s7 = "(null)"

	condition:
		6 of ( $s* )
}
rule JPCERTCC_Tscookie_1 {
    meta:
		description = "detect TSCookie in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "5407a5c9-2fc5-5b9b-977f-81384a343d15"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L8-L21"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "71e51ceb51cff25abefd698ce33f32388cc28ad5936f30fbbb9925d9af79ad85"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "6d2f5675630d0dae65a796ac624fb90f42f35fbe5dec2ec8f4adce5ebfaabf75"

	strings:
		$v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
		$b1 = { 68 D4 08 00 00 }

	condition:
		all of them
}
rule JPCERTCC_TSC_Loader {
    meta:
		description = "detect TSCookie Loader in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "378cc8a3-6a76-50d1-b1d2-1a6ca1a75a46"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L23-L35"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "c825253ba897f0f7310162d0473e645dc40b421e9251977384cca2fdc735f7a8"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
		$b1 = { 68 78 0B 00 00 }

	condition:
		all of them
}
rule JPCERTCC_Redleaves {
    meta:
		description = "detect RedLeaves in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "e17a85de-6a15-5de5-ba9e-03ac6d896d7d"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://blogs.jpcert.or.jp/en/2017/05/volatility-plugin-for-detecting-redleaves-malware.html"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L53-L66"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "c79815dd26070184688d43b336dc2be07df5e2236e60c8ecc42f5efec2cab190"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory block scan"
		hash1 = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"

	strings:
		$v1 = "red_autumnal_leaves_dllmain.dll"
		$b1 = { FF FF 90 00 }

	condition:
		$v1 and $b1 at 0
}
rule JPCERTCC_Himawari {
    meta:
		description = "detect Himawari(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "85c33dc6-0f9b-5645-b236-f416df16b4a4"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://www.jpcert.or.jp/present/2018/JSAC2018_01_nakatsuru.pdf"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L68-L82"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "9014e6e02fb9d8fa0f646c61647ab28c3cb08f10f8f584ddd11eba27211307f5"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

	strings:
		$h1 = "himawariA"
		$h2 = "himawariB"
		$h3 = "HimawariDemo"

	condition:
		all of them
}
rule JPCERTCC_Lavender {
    meta:
		description = "detect Lavender(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "8c30ae73-161f-5117-a1f9-fad0bd5278de"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L84-L97"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "bf64f927e2c8e9be0f11497f94357de8e3fadcf09ba224d6fec92841c89c1dc5"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"

	strings:
		$a1 = { C7 ?? ?? 4C 41 56 45 }
		$a2 = { C7 ?? ?? 4E 44 45 52 }

	condition:
		all of them
}
rule JPCERTCC_Armadill {
    meta:
		description = "detect Armadill(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "0e6fb091-5c26-5419-ac99-5ddc9db29fc0"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L99-L111"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "a76d434469a45e1c48b8ec3dc9622017c78ea52824006ddfcf3c368fbda7c912"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$a1 = { C7 ?? ?? 41 72 6D 61 }
		$a2 = { C7 ?? ?? 64 69 6C 6C }

	condition:
		all of them
}
rule JPCERTCC_Zark20Rk {
    meta:
		description = "detect zark20rk(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "baf3ebfe-80dd-5601-9ba9-8866b6ab6f14"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L113-L126"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "07c5c97916bd9ec19591d90f8b7d872fca571f3479148157cf1ee9e05c272e5c"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "d95ad7bbc15fdd112594584d92f0bff2c348f48c748c07930a2c4cc6502cd4b0"

	strings:
		$a1 = { C7 ?? ?? 7A 61 72 6B }
		$a2 = { C7 ?? ?? 32 30 72 6B }

	condition:
		all of them
}
rule JPCERTCC_Ursnif_1 {
    meta:
		description = "detect Ursnif(a.k.a. Dreambot, Gozi, ISFB) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "e93bc13b-33a9-5d9a-92a9-52f16a97fb16"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L128-L158"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "6c224b43e8ec0fa9540a1fdedce7ce4b97f8ab7196a9619594b7dcb9c2dc5169"
		score = 60
		quality = 60
		tags = ""
		rule_usage = "memory scan"
		hash1 = "0207c06879fb4a2ddaffecc3a6713f2605cbdd90fc238da9845e88ff6aef3f85"
		hash2 = "ff2aa9bd3b9b3525bae0832d1e2b7c6dfb988dc7add310088609872ad9a7e714"
		hash3 = "1eca399763808be89d2e58e1b5e242324d60e16c0f3b5012b0070499ab482510"

	strings:
		$a1 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
		$b1 = "client.dll" fullword
		$c1 = "version=%u"
		$c2 = "user=%08x%08x%08x%08x"
		$c3 = "server=%u"
		$c4 = "id=%u"
		$c5 = "crc=%u"
		$c6 = "guid=%08x%08x%08x%08x"
		$c7 = "name=%s"
		$c8 = "soft=%u"
		$d1 = "%s://%s%s"
		$d2 = "PRI \x2A HTTP/2.0"
		$e1 = { A1 ?? ?? ?? 00 35 E7 F7 8A 40 50 }
		$e2 = { 56 56 56 6A 06 5? FF ?? ?? ?? ?? 00 }
		$f1 = { 56 57 BE ?? ?? ?? ?? 8D ?? ?? A5 A5 A5 }
		$f2 = { 35 8F E3 B7 3F }
		$f3 = { 35 0A 60 2E 51 }

	condition:
		$a1 or ( $b1 and 3 of ( $c* ) ) or ( 5 of ( $c* ) ) or ( $b1 and all of ( $d* ) ) or all of ( $e* ) or all of ( $f* )
}
rule JPCERTCC_Emotet_1 {
    meta:
		description = "detect Emotet in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "f1cb5e3e-069d-54bb-829d-2ff4aa80e2bb"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L160-L176"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "32f6c25f324eb9f79b8f0b4bc37d648ed95d6347712208f13f74584ee164dc4f"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v4a = { BB 00 C3 4C 84 }
		$v4b = { B8 00 C3 CC 84 }
		$v5a = { 6D 4E C6 41 33 D2 81 C1 39 30 00 00 }
		$v6a = { C7 40 20 ?? ?? ?? 00 C7 40 10 ?? ?? ?? 00 C7 40 0C 00 00 00 00 83 3C CD ?? ?? ?? ?? 00 74 0E 41 89 48 ?? 83 3C CD ?? ?? ?? ?? 00 75 F2 }
		$v7a = { 6A 06 33 D2 ?? F7 ?? 8B DA 43 74 }
		$v7b = { 83 E6 0F 8B CF 83 C6 04 50 8B D6 E8 ?? ?? ?? ?? 59 6A 2F 8D 3C 77 58 66 89 07 83 C7 02 4B 75 }

	condition:
		all of ( $v4* ) or $v5a or $v6a or all of ( $v7* )
}
rule JPCERTCC_Smokeloader_1 {
    meta:
		description = "detect SmokeLoader in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "19666821-1fe9-50e7-958e-22f2260099aa"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://www.cert.pl/en/news/single/dissecting-smoke-loader/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L178-L191"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "11b7a297d3dcacba57de9b04a6d126970c2be9d5551f7976ac8129b0afbc9bfd"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$a1 = { B8 25 30 38 58 }
		$b1 = { 81 3D ?? ?? ?? ?? 25 00 41 00 }
		$c1 = { C7 ?? ?? ?? 25 73 25 73 }

	condition:
		$a1 and $b1 and $c1
}
rule JPCERTCC_Hawkeye {
    meta:
		description = "detect HawkEye in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "fc988aaf-bdac-5a53-a90c-d35d86285cd6"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L259-L272"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "45256e1e56de3934d2e57a7c036d49a0f56c25538ed7ad3eb7ee8efa7f549e98"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$hawkstr1 = "HawkEye Keylogger" wide
		$hawkstr2 = "Dear HawkEye Customers!" wide
		$hawkstr3 = "HawkEye Logger Details:" wide

	condition:
		all of them
}
rule JPCERTCC_Lokibot {
    meta:
		description = "detect Lokibot in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "12e8469b-83e9-5f93-a543-1c2efb4d303a"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L274-L288"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "3d2db6acb565d705ba26acb7f75be24096ab619a03726f4898391bfe5944bc46"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "6f12da360ee637a8eb075fb314e002e3833b52b155ad550811ee698b49f37e8c"

	strings:
		$des3 = { 68 03 66 00 00 }
		$param = "MAC=%02X%02X%02XINSTALL=%08X%08X"
		$string = { 2d 00 75 00 00 00 46 75 63 6b 61 76 2e 72 75 00 00}

	condition:
		all of them
}
rule JPCERTCC_Bebloh {
    meta:
		description = "detect Bebloh(a.k.a. URLZone) in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "7c3decb2-9cb5-5569-bab2-982c769ee233"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L290-L304"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "22b8ae9d40d34f83d8cc6c2dab56a866c8de8c9cc38b5da962c7071302f91f03"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$crc32f = { b8 EE 56 0b ca }
		$dga = "qwertyuiopasdfghjklzxcvbnm123945678"
		$post1 = "&vcmd="
		$post2 = "?tver="

	condition:
		all of them
}
rule JPCERTCC_Xxmm {
    meta:
		description = "detect xxmm in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "be459cbf-84a1-539e-b0b5-b7a00b6d278d"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L306-L319"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "4a860ac3efb97ce03fa906c2d0e7cd08654f6e82531d9449af7891be83a036d5"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v1 = "setupParameter:"
		$v2 = "loaderParameter:"
		$v3 = "parameter:"

	condition:
		all of them
}
rule JPCERTCC_Azorult_1 {
    meta:
		description = "detect Azorult in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "c73a007c-4d5f-5504-9635-9bffe1282aef"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L321-L334"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "158d65dcd8f3ce8fe4ab2d9bcc97edf585c1d665cc54e1e4969ef83c8103a149"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v1 = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)"
		$v2 = "http://ip-api.com/json"
		$v3 = { c6 07 1e c6 47 01 15 c6 47 02 34 }

	condition:
		all of them
}
rule JPCERTCC_Poisonivy {
    meta:
		description = "detect PoisonIvy in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "e7b27a88-490f-5f79-9e8c-65b8f7505a72"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L336-L349"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "dec7a95c877078f77cbcdcf8646680f6f1d55d438af98e519d13461a7854b095"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$a1 = { 0E 89 02 44 }
		$b1 = { AD D1 34 41 }
		$c1 = { 66 35 20 83 66 81 F3 B8 ED }

	condition:
		all of them
}
rule JPCERTCC_Netwire {
    meta:
		description = "detect netwire in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "cf71b80f-2618-5209-bb49-fefea9e0a7f3"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L351-L367"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "fa6ec967b6b3de226dcdb06d6b8f684800331a2420f038dd6274a8b9c3d8be78"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v1 = "HostId-%Rand%"
		$v2 = "mozsqlite3"
		$v3 = "[Scroll Lock]"
		$v4 = "GetRawInputData"
		$ping = "ping 192.0.2.2"
		$log = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"

	condition:
		($v1 ) or ( $v2 and $v3 and $v4 ) or ( $ping and $log )
}
rule JPCERTCC_Nanocore {
    meta:
		description = "detect Nanocore in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "0b12ad94-99c2-5d48-a860-ff75b82971af"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L369-L382"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "471dcda6f5fb9c30e3a1df7171fdba889114d54166d038d18c7910e2765d5250"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$v1 = "NanoCore Client"
		$v2 = "PluginCommand"
		$v3 = "CommandType"

	condition:
		all of them
}
rule JPCERTCC_Formbook_1 {
    meta:
		description = "detect Formbook in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "71291f9b-eb8e-55e5-a499-df54c35efdbf"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L384-L397"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "62bd3717af8970f67f28d923ce2483ff55a5ef4585a183d4d510e3a2c45fcc8c"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$sqlite3step = { 68 34 1c 7b e1 }
		$sqlite3text = { 68 38 2a 90 c5 }
		$sqlite3blob = { 68 53 d8 7f 8c }

	condition:
		all of them
}
rule JPCERTCC_Agenttesla_Type1 {
    meta:
		description = "detect Agenttesla in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "92bfb3ab-d8d0-50ec-8ab8-ad34f1edb906"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L399-L411"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "24b9b815400967a9086048527f7aa1fce08bcd94a16aec8080aeac97045b297a"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$iestr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\IELibrary\\\\IELibrary\\\\obj\\\\Debug\\\\IELibrary.pdb"
		$atstr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\ConsoleApp1\\\\ConsoleApp1\\\\obj\\\\Debug\\\\ConsoleApp1.pdb"
		$sqlitestr = "Not a valid SQLite 3 Database File" wide

	condition:
		all of them
}
rule JPCERTCC_Noderat {
    meta:
		description = "detect Noderat in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "9c2c4b0f-0f45-54f6-a98c-b592af882eef"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://blogs.jpcert.or.jp/ja/2019/02/tick-activity.html"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L429-L442"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "e1254b6cf28161943db202ea0a6ff2d86aa7975d4a3ecc0f26eed58101e54960"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"

	strings:
		$config = "/config/app.json"
		$key = "/config/.regeditKey.rc"
		$message = "uninstall error when readFileSync: "

	condition:
		all of them
}
rule JPCERTCC_Njrat {
    meta:
		description = "detect njRAT in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "96b35796-3e1d-5721-998a-e678612e4de7"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://github.com/JPCERTCC/MalConfScan/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L444-L456"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "398614ff5ea37dfaf6c36f60702cb7cdfe66b4569c698e9c3ea29563e4031856"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "d5f63213ce11798879520b0e9b0d1b68d55f7727758ec8c120e370699a41379d"

	strings:
		$reg = "SEE_MASK_NOZONECHECKS" wide fullword
		$msg = "Execute ERROR" wide fullword
		$ping = "cmd.exe /c ping 0 -n 2 & del" wide fullword

	condition:
		all of them
}
rule JPCERTCC_Trickbot {
    meta:
		description = "detect TrickBot in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "1a3c5193-bea1-5f64-be40-47bd22c09772"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://github.com/JPCERTCC/MalConfScan/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L458-L478"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "b0c3437bc4b4f9e7b2a1562e2d514b7aad398d5e387bb79829757b5772a1ebc3"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "2153be5c6f73f4816d90809febf4122a7b065cbfddaa4e2bf5935277341af34c"

	strings:
		$tagm1 = "<mcconf><ver>" wide
		$tagm2 = "</autorun></mcconf>" wide
		$tagc1 = "<moduleconfig><autostart>" wide
		$tagc2 = "</autoconf></moduleconfig>" wide
		$tagi1 = "<igroup><dinj>" wide
		$tagi2 = "</dinj></igroup>" wide
		$tags1 = "<servconf><expir>" wide
		$tags2 = "</plugins></servconf>" wide
		$tagl1 = "<slist><sinj>" wide
		$tagl2 = "</sinj></slist>" wide
		$dllname = { 6C 00 00 00 CC 00 00 00 19 01 00 00 00 00 00 00 1A 01 }

	condition:
		all of ( $tagm* ) or all of ( $tagc* ) or all of ( $tagi* ) or all of ( $tags* ) or all of ( $tagl* ) or $dllname
}
rule JPCERTCC_Remcos_1 {
    meta:
		description = "detect Remcos in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "4a27a16a-2669-5009-bc82-082ec0c9b2c1"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://github.com/JPCERTCC/MalConfScan/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L480-L493"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "1b4b9f7a88f33faeda71ea9a354eeccba8889800f48a6280c4ec533bb1b3ef3d"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "7d5efb7e8b8947e5fe1fa12843a2faa0ebdfd7137582e5925a0b9c6a9350b0a5"

	strings:
		$remcos = "Remcos" ascii fullword
		$url1 = "Breaking-Security.Net" ascii fullword
		$url2 = "BreakingSecurity.Net" ascii fullword
		$resource = "SETTINGS" ascii wide fullword

	condition:
		1 of ( $url* ) and $remcos and $resource
}
rule JPCERTCC_Quasar {
    meta:
		description = "detect QuasarRAT in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "f0a81a46-c19b-5012-a1a2-f2f4310fcde3"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://github.com/JPCERTCC/MalConfScan/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L495-L513"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "a3bb45f2ea217ae1825d80e1ead9c3e47ca88575c960ce1f9feb2db09f489e08"
		score = 75
		quality = 80
		tags = ""
		rule_usage = "memory scan"
		hash1 = "390c1530ff62d8f4eddff0ac13bc264cbf4183e7e3d6accf8f721ffc5250e724"

	strings:
		$quasarstr1 = "Client.exe" wide
		$quasarstr2 = "({0}:{1}:{2})" wide
		$sql1 = "SELECT * FROM Win32_DisplayConfiguration" wide
		$sql2 = "{0}d : {1}h : {2}m : {3}s" wide
		$sql3 = "SELECT * FROM FirewallProduct" wide
		$net1 = "echo DONT CLOSE THIS WINDOW!" wide
		$net2 = "freegeoip.net/xml/" wide
		$net3 = "http://api.ipify.org/" wide
		$resource = { 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73 00 00 17 69 00 6E 00 66 00 6F 00 72 00 6D 00 61 00 74 00 69 00 6F 00 6E 00 00 }

	condition:
		(( all of ( $quasarstr* ) or all of ( $sql* ) ) and $resource ) or all of ( $net* )
}
rule JPCERTCC_Asyncrat {
    meta:
		description = "detect AsyncRat in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "758614e8-df93-54ff-9f06-0020b54fbf88"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "internal research"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L531-L548"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		logic_hash = "0a60718ea3412129c40e2eee53591dbf094a6b914502242b5ab9b54f8fd95da0"
		score = 75
		quality = 76
		tags = ""
		rule_usage = "memory scan"
		hash1 = "1167207bfa1fed44e120dc2c298bd25b7137563fdc9853e8403027b645e52c19"
		hash2 = "588c77a3907163c3c6de0e59f4805df41001098a428c226f102ed3b74b14b3cc"

	strings:
		$salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
		$b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00}
		$b2 = {09 50 00 6F 00 6E 00 67 00 00}
		$s1 = "pastebin" ascii wide nocase
		$s2 = "pong" wide
		$s3 = "Stub.exe" ascii wide

	condition:
		($salt and ( 2 of ( $s* ) or 1 of ( $b* ) ) ) or ( all of ( $b* ) and 2 of ( $s* ) )
}
rule CHECK_POINT_Malware_Bumblebee_Packed {
    meta:
		description = "Detects the packer used by bumblebee, the rule is based on the code responsible for allocating memory for a critical structure in its logic."
		author = "Marc Salinas @ CheckPoint Research"
		id = "35f00c87-c26e-5189-b66d-15d5a1b1dd20"
		date = "2022-07-13"
		modified = "2023-04-10"
		reference = "https://research.checkpoint.com/2022/bumblebee-increasing-its-capacity-and-evolving-its-ttps/"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Checkpoint/malware_bumblebee_packed.yar#L1-L31"
		license_url = "N/A"
		logic_hash = "063209aad7ab8a0be46fd578a16b04afc086f930cbdb6c2f7b02824f704d7330"
		score = 75
		quality = 85
		tags = ""
		malware_family = "BumbleBee"
		dll_jul = "6bc2ab410376c1587717b2293f2f3ce47cb341f4c527a729da28ce00adaaa8db"
		dll_jun = "82aab01a3776e83695437f63dacda88a7e382af65af4af1306b5dbddbf34f9eb"
		dll_may = "a5bcb48c0d29fbe956236107b074e66ffc61900bc5abfb127087bb1f4928615c"
		iso_jul = "ca9da17b4b24bb5b24cc4274cc7040525092dffdaa5922f4a381e5e21ebf33aa"
		iso_jun = "13c573cad2740d61e676440657b09033a5bec1e96aa1f404eed62ba819858d78"
		iso_may = "b2c28cdc4468f65e6fe2f5ef3691fa682057ed51c4347ad6b9672a9e19b5565e"
		zip_jun = "7024ec02c9670d02462764dcf99b9a66b29907eae5462edb7ae974fe2efeebad"
		zip_may = "68ac44d1a9d77c25a97d2c443435459d757136f0d447bfe79027f7ef23a89fce"

	strings:
		$heapalloc = {  
            48 8? EC [1-6]           // sub     rsp, 80h 
            FF 15 ?? ?? 0? 00 [0-5]  // call    cs:GetProcessHeap 
            33 D2                    // xor     edx, edx        ; dwFlags 
            4? [2-5]                 // mov     rcx, rax        ; hHeap 
            4? ?? ??                 // mov     r8d, ebx        ; dwBytes 
            FF 15 ?? ?? 0? 00        // call    cs:HeapAlloc 
            [8 - 11]                 // (load params) 
            48 89 05 ?? ?? ?? 00     // mov     cs:HeapBufferPtr, rax 
            E8 ?? ?? ?? ??           // call    memset 
            4? 8B ?? ?? ?? ?? 00     // mov     r14, cs:HeapBufferPtr 
        }

	condition:
		$heapalloc
}
rule DRAGON_THREAT_LABS_Apt_C16_Win_Memory_Pcclient : MEMORY APT {
    meta:
		description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
		author = "@dragonthreatlab"
		id = "59333cd4-b532-510e-afe5-fc3b2e96698f"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L4-L19"
		license_url = "N/A"
		hash = "ec532bbe9d0882d403473102e9724557"
		logic_hash = "e863fcbcbde61db569a34509061732371143f38734a0213dc856dc3c9188b042"
		score = 75
		quality = 80
		tags = "MEMORY, APT"

	strings:
		$str1 = "Kill You" ascii
		$str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
		$str3 = "%4.2f  KB" ascii
		$encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}

	condition:
		all of them
}
rule DRAGON_THREAT_LABS_Apt_C16_Win_Swisyn : MEMORY FILE {
    meta:
		description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
		author = "@dragonthreatlab"
		id = "af369075-aca3-576d-a10b-849703ffb4f1"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L54-L70"
		license_url = "N/A"
		hash = "a6a18c846e5179259eba9de238f67e41"
		logic_hash = "2fa29d3b17aa37501131132640953645d0089c9bc5ec13ffed7a498ad89c1558"
		score = 75
		quality = 28
		tags = "MEMORY, FILE"

	strings:
		$mz = {4D 5A}
		$str1 = "/ShowWU" ascii
		$str2 = "IsWow64Process"
		$str3 = "regsvr32 "
		$str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}

	condition:
		$mz at 0 and all of ( $str* )
}
rule NCSC_Sparrowdoor_Shellcode {
    meta:
		description = "Targets code features of the reflective loader for SparrowDoor. Targeting in memory."
		author = "NCSC"
		id = "572187fb-1a11-54f2-9fe7-2b7468b56556"
		date = "2022-02-28"
		modified = "2022-07-06"
		reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/SparrowDoor_shellcode.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "7186bab23114b4825161f58fb02ff397ec8278385482232a4086c86c6fc47082"
		score = 75
		quality = 80
		tags = ""
		hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

	strings:
		$peb = {8B 48 08 89 4D FC 8B 51 3C 8B 54 0A 78 8B 74 0A 20 03 D1 03 F1 B3 64}
		$getp_match = {8B 06 03 C1 80 38 47 75 34 80 78 01 65 75 2E 80 78 02 74 75 28 80 78 03 50 75 22 80 78 04 72 75 1C 80 78 06 63 75 16 80 78 05 6F 75 10 80 78 07 41 75 0A}
		$k_check = {8B 48 20 8A 09 80 F9 6B 74 05 80 F9 4B 75 05}
		$resolve_load_lib = {C7 45 C4 4C 6F 61 64 C7 45 C8 4C 69 62 72 C7 45 CC 61 72 79 41 C7 45 D0 00 00 00 00 FF 75 FC FF 55 E4}

	condition:
		3 of them
}
rule NCSC_Sparrowdoor_Strings {
    meta:
		description = "Strings that appear in SparrowDoor’s backdoor. Targeting in memory."
		author = "NCSC"
		id = "6f96a577-fb59-57db-a66a-f514ecfbf982"
		date = "2022-02-28"
		modified = "2022-07-06"
		reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/SparrowDoor_strings.yar#L1-L23"
		license_url = "N/A"
		logic_hash = "65ec5d266ecd81ab8e4cfbcb352173f825bdae92fd4737b577cb209bace2a943"
		score = 75
		quality = 80
		tags = ""
		hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

	strings:
		$reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
		$http_headers = {55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 35 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 35 2E 30 29 0D 0A 41 63 63 65 70 74 2D 4C 61 6E 67 75 61 67 65 3A 20 65 6E 2D 55 53 0D 0A 41 63 63 65 70 74 3A 20 2A 2F 2A 0D 0A}
		$http_proxy = "HTTPS=HTTPS://%s:%d" ascii
		$debug = "SeDebugPrivilege" ascii
		$av1 = "avp.exe" ascii
		$av2 = "ZhuDongFangYu.exe" ascii
		$av3 = "egui.exe" ascii
		$av4 = "TMBMSRV.exe" ascii
		$av5 = "ccSetMgr.exe" ascii
		$clipshot = "clipshot" ascii
		$ComSpec = "ComSpec" ascii
		$export = "curl_easy_init" ascii

	condition:
		10 of them
}
rule NCSC_Sparrowdoor_Xor {
    meta:
		description = "Highlights XOR routines in SparrowDoor. No MZ/PE match as the backdoor has no header. Targeting in memory."
		author = "NCSC"
		id = "9c07feea-91fc-528e-91ac-14d09fa1fc10"
		date = "2022-02-28"
		modified = "2022-07-06"
		reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/SparrowDoor_xor.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "3244e9017e5a0bf1c54e03b3191a5c695b2c1586b3ed4c529742f9b48903a348"
		score = 75
		quality = 80
		tags = ""
		hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

	strings:
		$xor_routine_outbound = {B8 39 8E E3 38 F7 E1 D1 EA 8D 14 D2 8B C1 2B C2 8A [4] 00 30 14 39 41 3B CE}
		$xor_routine_inbound = {B8 25 49 92 24 F7 E1 8B C1 2B C2 D1 E8 03 C2 C1 E8 02 8D 14 C5 [4] 2B D0 8B C1 2B C2}
		$xor_routine_config = {8B D9 83 E3 07 0F [6] 30 18 8D 1C 07 83 E3 07 0F [6] 30 58 01 8D 1C 28 83 E3 07 0F [6] 30 58 02 8D 1C 02 83 E3 07 0F [6] 30 58 03 8B DE 83 E3 07 0F [6] 30 58 04 83 C6 05 83 C1 05}

	condition:
		2 of them
}
rule NCSC_Sparrowdoor_Apipatch {
    meta:
		description = "Identifies code segments in SparrowDoor responsible for patching APIs. No MZ/PE match as the backdoor has no header. Targeting in memory."
		author = "NCSC"
		id = "119b7f3a-1850-53ab-a5d1-8882e34a34b4"
		date = "2022-02-28"
		modified = "2022-07-06"
		reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/SparrowDoor_apipatch.yar#L1-L17"
		license_url = "N/A"
		logic_hash = "302ad7fc0354636c57e6ec86876c7d4a5baaa784f5ecf0f2d51ce47631b8542a"
		score = 75
		quality = 80
		tags = ""
		hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

	strings:
		$save = {8B 06 89 07 8A 4E 04}
		$vp_1 = {89 10 8A 4E 04 8B D6 2B D0 88 48 04 83 EA 05 C6 40 05 E9 89 50 06}
		$vp_2 = {50 8B D6 6A 40 2B D7 88 4F 04 83 EA 05 6A 05 C6 47 05 E9 89 57 06 56}
		$vp_3 = {51 52 2B DE 6A 05 83 EB 05 56 C6 06 E9 89 5E 01}
		$va = {6A 40 68 00 10 00 00 68 00 10 00 00 6A 00}
		$s_patch = {50 68 7F FF FF FF 68 FF FF 00 00 56}

	condition:
		3 of them
}
rule SBOUSSEADEN_Mimikatz_Memssp_Hookfn {
    meta:
		description = "hunt for default mimikatz memssp module both ondisk and in memory artifacts"
		author = "SBousseaden"
		id = "845827b1-acd4-53af-97fb-43a4fe355fbf"
		date = "2020-08-26"
		modified = "2020-08-26"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/mimikatz_memssp_hookfn.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "f63f3de05dd4f4f40cda6df67b75e37d7baa82c4b4cafd3ebdca35adfb0b15f8"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = {44 30 00 38 00}
		$s2 = {48 78 00 3A 00}
		$s3 = {4C 25 00 30 00}
		$s4 = {50 38 00 78 00}
		$s5 = {54 5D 00 20 00}
		$s6 = {58 25 00 77 00}
		$s7 = {5C 5A 00 5C 00}
		$s8 = {60 25 00 77 00}
		$s9 = {64 5A 00 09 00}
		$s10 = {6C 5A 00 0A 00}
		$s11 = {68 25 00 77 00}
		$s12 = {68 25 00 77 00}
		$s13 = {6C 5A 00 0A 00}
		$B = {6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67}

	condition:
		all of ( $s* ) or $B
}
rule SBOUSSEADEN_Hunt_Evtmutehook_Memory {
    meta:
		description = "memory hunt for default wevtsv EtwEventCallback hook pattern to apply to eventlog svchost memory dump"
		author = "SBousseaden"
		id = "5326581e-90d9-59b9-8dc5-74df97571600"
		date = "2020-09-05"
		modified = "2020-09-05"
		reference = "https://blog.dylan.codes/pwning-windows-event-logging/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_memory_evtmutehook.yara#L1-L11"
		license_url = "N/A"
		logic_hash = "3db66069ed67d90031a6fe071dad4d0200ddd661b263dd2860df026673031e48"
		score = 50
		quality = 75
		tags = ""

	strings:
		$a = {49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3 54 24 20 4C 8B 05 61 CB 1A 00 0F 57 C0 66 0F 7F 44 24 20 E8 5B 0A 00 00 48 83 C4 38 C3}
		$b = {48 83 EC 38 4C 8B 0D 65 CB 1A 00 48 8D 54 24 20 4C 8B 05 61 CB 1A 00 0F 57 C0 66 0F 7F 44 24 20 E8 5B 0A 00 00 48 83 C4 38 C3}

	condition:
		$a and not $b
}
rule DITEKSHEN_MALWARE_Win_Quilclipper {
    meta:
		description = "Detects QuilClipper variants mostly in memory or extracted AutoIt script"
		author = "ditekSHen"
		id = "bd23ec5a-f21a-5133-a77a-de2615933b82"
		date = "2024-11-01"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L4076-L4094"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "dcac93806a438b188ae70a679301cb6630b9eb6849bf8fbbb1cea5fed5e7cf75"
		score = 75
		quality = 75
		tags = ""

	strings:
		$cnc1 = "QUILCLIPPER by" ascii
		$cnc2 = "/ UserName:" ascii
		$cnc3 = "/ System:" ascii
		$s1 = "DLLCALL ( \"kernel32.dll\" , \"handle\" , \"CreateMutexW\" , \"struct*\"" ascii
		$s2 = "SHELLEXECUTE ( @SCRIPTFULLPATH , \"\" , \"\" , FUNC_" ascii
		$s3 = "CASE BITROTATE" ascii
		$s4 = "CASE BITXOR" ascii
		$s5 = "CLIP( FUNC_" ascii
		$s6 = "CLIPPUT (" ascii
		$s7 = "FUNC _CLIPPUTFILE(" ascii
		$s8 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Schedule" ascii

	condition:
		all of ( $cnc* ) or all of ( $s* )
}
rule DITEKSHEN_MALWARE_Win_Scouteliteps {
    meta:
		description = "Detects actor PowerShell tool designed to steal browsers session cookie and passwords on-disk and in-memory"
		author = "ditekshen"
		id = "d2c04d55-9bf7-54f5-8053-835fa60f19cb"
		date = "2024-11-01"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/back-in-2017"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L11534-L11569"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "9b1047b8b485fcfa29225f53674050703d32498cfa99654c8ac5f8bfac29878e"
		score = 75
		quality = 37
		tags = ""

	strings:
		$cnc1 = "http://beginpassport.com" ascii wide nocase
		$cnc2 = "f_dump.php" ascii wide nocase
		$cnc3 = "c_dump.php" ascii wide nocase
		$cnc4 = "o_dump.php" ascii wide nocase
		$db1 = "\\Google\\Chrome\\User Data\\Default\\Cookies" ascii wide nocase
		$db2 = "\\Mozilla\\Firefox\\Profiles\\*.default" ascii wide nocase
		$db3 = "\\Opera Software\\Opera Stable\\Cookies" ascii wide nocase
		$db4 = "$($env:LOCALAPPDATA)\\Google\\Chrome\\User Data\\Default" ascii nocase
		$db5 = "$($env:APPDATA)\\Mozilla\\Firefox\\Profiles\\*.default" ascii nocase
		$db6 = "$($env:APPDATA)\\Opera Software\\Opera Stable" ascii nocase
		$cond1 = "SSID" ascii wide
		$cond2 = "MSPAuth" ascii wide
		$cond3 = "\"'T'\"" ascii wide
		$cond4 = "SNS_AA" ascii wide
		$cond5 = "X-APPLE-WEBAUTH-TOKEN" ascii wide
		$sql1 = "SELECT * FROM 'cookies' WHERE host_key LIKE $" ascii wide nocase
		$sql2 = "SELECT * FROM 'moz_cookies' WHERE host LIKE $" ascii wide nocase
		$sql3 = "SELECT origin_url, username_value ,password_value FROM 'logins'" ascii nocase
		$def1 = "Add-Type -AssemblyName System.Security" ascii wide nocase
		$def2 = "System.Security.SecureString" ascii wide nocase
		$def3 = "ConvertFrom-SecureString" ascii wide nocase
		$def4 = "[System.Security.Cryptography.ProtectedData]::Unprotect(" ascii wide nocase
		$def5 = "[Security.Cryptography.DataProtectionScope]::LocalMachine" ascii wide nocase
		$def6 = "[Security.Cryptography.DataProtectionScope]::CurrentUser" ascii wide nocase
		$def7 = "System.Data.SQLite.SQLiteConnection" ascii wide nocase
		$def8 = "[Environment]::OSVersion.ToString().Replace(\"Microsoft Windows \"," ascii wide nocase
		$def9 = "Start-Sleep" ascii wide nocase

	condition:
		(1 of ( $cnc* ) and any of ( $db* ) and any of ( $cond* ) and any of ( $sql* ) and 7 of ( $def* ) ) or ( all of them )
}
rule HARFANGLAB_Allasenhamaycampaign_Executorloader {
    meta:
		description = "Detects Delphi ExecutorLoader DLLs and executables."
		author = "HarfangLab"
		id = "0a09414d-cd86-54a4-99e4-121a7df7624b"
		date = "2024-05-28"
		modified = "2025-06-23"
		reference = "TRR240501"
		source_url = "https://github.com/HarfangLab/iocs/blob/8dc3aaf1321031ddbd35668b4033701413418f92/hl_public_reports_master.yar#L96-L114"
		license_url = "N/A"
		logic_hash = "61aa0bf180574856e57d0b26442bfa6f4b1e25844611d6eadaed529e1bb86625"
		score = 75
		quality = 55
		tags = ""
		context = "file,memory"

	strings:
		$delphi = "Embarcadero Delphi" ascii fullword
		$s1 = "\\SysWOW64\\mshta.exe" wide fullword
		$s2 = "\\System32\\mshta.exe" wide fullword
		$s3 = "RcDll" wide fullword
		$default1 = "Default_" wide fullword
		$default2 = "Default~" wide fullword

	condition:
		$delphi and all of ( $s* ) and any of ( $default* )
}
rule HARFANGLAB_Allasenhamaycampaign_Allasenha {
    meta:
		description = "Detects AllaSenha banking trojan DLLs."
		author = "HarfangLab"
		id = "787c4e66-2053-5f14-a52e-6b0415700e8c"
		date = "2024-05-28"
		modified = "2025-06-23"
		reference = "TRR240501"
		source_url = "https://github.com/HarfangLab/iocs/blob/8dc3aaf1321031ddbd35668b4033701413418f92/hl_public_reports_master.yar#L115-L137"
		license_url = "N/A"
		logic_hash = "affe75ade6c8d9eeba00006f78678a48b1cfc5ffa9f9675fdea6ffd6cb3a02bd"
		score = 75
		quality = 80
		tags = ""
		context = "file,memory"

	strings:
		$a1 = "<|NOSenha|>" wide fullword
		$a2 = "<|SENHA|>QrCode: " wide fullword
		$a3 = "<|SENHA|>Senha 6 : " wide fullword
		$a4 = "<|SENHA|>Snh: " wide fullword
		$a5 = "<|SENHA|>Token: " wide fullword
		$a6 = "<|BB-AMARELO|>" wide fullword
		$a7 = "<|BB-AZUL|>" wide fullword
		$a8 = "<|BB-PROCURADOR|>" wide fullword
		$a9 = "<|ITAU-SNH-CARTAO|>" wide fullword
		$a10 = "<|ITAU-TK-APP|>" wide fullword
		$dga = { 76 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 78 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 7A 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 77 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 6B 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 79 00 00 00 }

	condition:
		$dga and ( 4 of ( $a* ) )
}
rule HARFANGLAB_Nhas_Reverse_Shell_Pe_Inmem_Large {
    meta:
		description = "Matches packed NHAS reverse_ssh PE samples in-memory during execution"
		author = "HarfangLab"
		id = "f6b38e11-c405-5623-bea3-3a8d96b435af"
		date = "2024-09-24"
		modified = "2025-06-23"
		reference = "TRR250201"
		source_url = "https://github.com/HarfangLab/iocs/blob/8dc3aaf1321031ddbd35668b4033701413418f92/hl_public_reports_master.yar#L276-L294"
		license_url = "N/A"
		hash = "7798b45ffc488356f7253805dc9c8d2210552bee39db9082f772185430360574"
		logic_hash = "b9bbbbd93dc39f8c16c7f8275fa73f4c345c3ba8f21da76ae491e89d3a22c473"
		score = 75
		quality = 80
		tags = ""
		context = "memory"

	strings:
		$s1 = "\\rprichard\\proj\\winpty\\src\\agent\\" ascii
		$s2 = "\\Users\\mail\\source\\winpty\\src\\" ascii
		$s3 = "Successfully connnected" ascii
		$s4 = "*main.decFunc" ascii fullword
		$s6 = "keepalive-rssh@golang.org" ascii fullword
		$s7 = ".(*sshFxpSetstatPacket)." ascii

	condition:
		( all of them )
}
rule SEKOIA_Apt_Unk_Hrserv_Memory_Commands_Strings {
    meta:
		description = "Detects HrServ web shell memory commands"
		author = "Sekoia.io"
		id = "1b5f442a-e758-4bd5-a612-8b504a542d29"
		date = "2023-11-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/a47734fa931e56f8646dab2abf31629431982429/yara_rules/apt_unk_hrserv_memory_commands_strings.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/a47734fa931e56f8646dab2abf31629431982429/LICENSE.md"
		logic_hash = "a87c35658ded301c098f9ee8ee5886a54e89537eabd145cf82b0286c703a77d2"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "list all the process" ascii wide
		$ = "equal with cmd /c tasklist" ascii wide
		$ = "start target service by name" ascii wide
		$ = "query local process information by wmi." ascii wide
		$ = "upload local shellcode to" ascii wide

	condition:
		all of them
}
rule SIGNATURE_BASE_Mimikatz_Memory_Rule_1 : APT {
    meta:
		description = "Detects password dumper mimikatz in memory (False Positives: an service that could have copied a Mimikatz executable, AV signatures)"
		author = "Florian Roth"
		id = "55cc7129-5ea0-5545-a8f6-b5306a014dd0"
		date = "2014-12-22"
		modified = "2023-07-04"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/gen_mimikatz.yar#L5-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "22064af570b8e0a93ca0d45484848eda3fbecfd27c88247ef0897fe53be4b7fc"
		score = 70
		quality = 85
		tags = "APT"
		nodeepdive = 1

	strings:
		$s1 = "sekurlsa::wdigest" fullword ascii
		$s2 = "sekurlsa::logonPasswords" fullword ascii
		$s3 = "sekurlsa::minidump" fullword ascii
		$s4 = "sekurlsa::credman" fullword ascii
		$fp1 = "\"x_mitre_version\": " ascii
		$fp2 = "{\"type\":\"bundle\","
		$fp3 = "use strict" ascii fullword
		$fp4 = "\"url\":\"https://attack.mitre.org/" ascii

	condition:
		1 of ( $s* ) and not 1 of ( $fp* )
}
rule SIGNATURE_BASE_HKTL_Mimikatz_Skeletonkey_In_Memory_Aug20_1 {
    meta:
		description = "Detects Mimikatz SkeletonKey in Memory"
		author = "Florian Roth (Nextron Systems)"
		id = "e7c1c512-e944-5d87-ac57-cdc9ab7cf660"
		date = "2020-08-09"
		modified = "2023-12-05"
		reference = "https://twitter.com/sbousseaden/status/1292143504131600384?s=12"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/gen_mimikatz.yar#L178-L190"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "0cc9a4d3b63e07a695df342bd2c96a55570502d6fd0ab9a1b61d63e28e1c3e05"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = { 60 ba 4f ca c7 44 24 34 dc 46 6c 7a c7 44 24 38 
              03 3c 17 81 c7 44 24 3c 94 c0 3d f6 }

	condition:
		1 of them
}
rule SIGNATURE_BASE_HKTL_Mimikatz_Memssp_Hookfn {
    meta:
		description = "Detects Default Mimikatz memssp module in-memory"
		author = "SBousseaden"
		id = "89940110-8a5e-5a28-bf64-3b568f8ef1f8"
		date = "2020-08-26"
		modified = "2023-12-05"
		reference = "https://github.com/sbousseaden/YaraHunts/blob/master/mimikatz_memssp_hookfn.yara"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/gen_mimikatz.yar#L192-L216"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "27cf87f801111f17af76ab4c4f8329b73165f24f755d33edbb22d845bba6d3ff"
		score = 70
		quality = 85
		tags = ""

	strings:
		$xc1 = { 48 81 EC A8 00 00 00 C7 84 24 88 00 00 00 ?? ?? 
               ?? ?? C7 84 24 8C 00 00 00 ?? ?? ?? ?? C7 84 24 
               90 00 00 00 ?? ?? ?? 00 C7 84 24 80 00 00 00 61 
               00 00 00 C7 44 24 40 5B 00 25 00 C7 44 24 44 30 
               00 38 00 C7 44 24 48 78 00 3A 00 C7 44 24 4C 25 
               00 30 00 C7 44 24 50 38 00 78 00 C7 44 24 54 5D 
               00 20 00 C7 44 24 58 25 00 77 00 C7 44 24 5C 5A 
               00 5C 00 C7 44 24 60 25 00 77 00 C7 44 24 64 5A 
               00 09 00 C7 44 24 68 25 00 77 00 C7 44 24 6C 5A 
               00 0A 00 C7 44 24 70 00 00 00 00 48 8D 94 24 80 
               00 00 00 48 8D 8C 24 88 00 00 00 48 B8 A0 7D ?? 
               ?? ?? ?? 00 00 FF D0 }

	condition:
		$xc1
}
rule SIGNATURE_BASE_APT_Dropper_Raw64_TEARDROP_1 {
    meta:
		description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
		author = "FireEye"
		id = "88adad58-ba16-5996-9ea8-ea356c3ed5b2"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/apt_solarwinds_sunburst.yar#L141-L156"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "6ab5197e7a1a123055b361a2ef79f8a77a7935606fccc8f163ea5914c94cd14d"
		score = 85
		quality = 85
		tags = ""

	strings:
		$sb1 = { C7 44 24 ?? 80 00 00 00 [0-64] BA 00 00 00 80 [0-32] 48 8D 0D [4-32] FF 15 [4] 48 83 F8 FF [2-64] 41 B8 40 00 00 00 [0-64] FF 15 [4-5] 85 C0 7? ?? 80 3D [4] FF }
		$sb2 = { 80 3D [4] D8 [2-32] 41 B8 04 00 00 00 [0-32] C7 44 24 ?? 4A 46 49 46 [0-32] E8 [4-5] 85 C0 [2-32] C6 05 [4] 6A C6 05 [4] 70 C6 05 [4] 65 C6 05 [4] 67 }
		$sb3 = { BA [4] 48 89 ?? E8 [4] 41 B8 [4] 48 89 ?? 48 89 ?? E8 [4] 85 C0 7? [1-32] 8B 44 24 ?? 48 8B ?? 24 [1-16] 48 01 C8 [0-32] FF D0 }

	condition:
		all of them
}
rule SIGNATURE_BASE_APT_MAL_RU_WIN_Snake_Malware_May23_1 : MEMORY {
    meta:
		description = "Hunting Russian Intelligence Snake Malware"
		author = "Matt Suiche (Magnet Forensics)"
		id = "53d2de3c-350c-5090-84bb-b6cde16a80ad"
		date = "2023-05-10"
		modified = "2025-03-21"
		reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/apt_mal_ru_snake_may23.yar#L17-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "7cff7152259bb17a9b72b91f0fbef220aad2f35a1d2758d7225316a9896bf845"
		score = 70
		quality = 71
		tags = "MEMORY"
		threat_name = "Windows.Malware.Snake"
		scan_context = "memory"
		license = "MIT"

	strings:
		$a = { 25 73 23 31 }
		$b = { 25 73 23 32 }
		$c = { 25 73 23 33 }
		$d = { 25 73 23 34 }
		$e = { 2e 74 6d 70 }
		$g = { 2e 73 61 76 }
		$h = { 2e 75 70 64 }

	condition:
		all of them
}
rule SIGNATURE_BASE_Fidelis_Advisory_Cedt370 {
    meta:
		description = "Detects a string found in memory of malware cedt370r(3).exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b5ebf2d7-e3e4-5b3b-a082-417da9c7fda6"
		date = "2015-06-09"
		modified = "2023-12-05"
		reference = "http://goo.gl/ZjJyti"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/apt_fidelis_phishing_plain_sight.yar#L16-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "1070d3c63a7091c0982e67134f9dc3cd790bb0b5c2ac08f3a00e3b97ef53d64b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "PO.exe" ascii fullword
		$s1 = "Important.exe" ascii fullword
		$s2 = "&username=" ascii fullword
		$s3 = "Browsers.txt" ascii fullword

	condition:
		all of them
}
rule SIGNATURE_BASE_HKTL_Meterpreter_Inmemory {
    meta:
		description = "Detects Meterpreter in-memory"
		author = "netbiosX, Florian Roth"
		id = "29c3bb7e-4da8-5924-ada7-2f28d9352009"
		date = "2020-06-29"
		modified = "2023-04-21"
		reference = "https://www.reddit.com/r/purpleteamsec/comments/hjux11/meterpreter_memory_indicators_detection_tooling/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/gen_metasploit_payloads.yar#L341-L363"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "4b39dbcb276842a1306205cf2e51ce86b6d2aa21353d277df15f4ea3b3d97678"
		score = 85
		quality = 85
		tags = ""

	strings:
		$sxc1 = { 6D 65 74 73 72 76 2E 64 6C 6C 00 00 52 65 66 6C 
               65 63 74 69 76 65 4C 6F 61 64 65 72 }
		$sxs1 = "metsrv.x64.dll" ascii fullword
		$ss1 = "WS2_32.dll" ascii fullword
		$ss2 = "ReflectiveLoader" ascii fullword
		$fp1 = "SentinelOne" ascii wide
		$fp2 = "fortiESNAC" ascii wide
		$fp3 = "PSNMVHookMS" ascii wide

	condition:
		(1 of ( $sx* ) or 2 of ( $s* ) ) and not 1 of ( $fp* )
}
rule SIGNATURE_BASE_APT_Backdoor_Win_Gorat_Memory_1 {
    meta:
		description = "Identifies GoRat malware in memory based on strings."
		author = "FireEye"
		id = "4fcdd98f-1873-58e1-a9f5-73ee0aa5a69f"
		date = "2025-02-12"
		modified = "2025-02-12"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/gen_fireeye_redteam_tools.yar#L1013-L1039"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		hash = "3b926b5762e13ceec7ac3a61e85c93bb"
		logic_hash = "bf8d80b7a7d35c1bcb353ff66d10bc95c2e6502043acc6554887465a467cdcf7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$rat1 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
		$rat2 = "rat.(*Core).generateBeacon" fullword
		$rat3 = "rat.gJitter" fullword
		$rat4 = "rat/comms.(*protectedChannel).SendCmdResponse" fullword
		$rat5 = "rat/modules/filemgmt.(*acquire).NewCommandExecution" fullword
		$rat6 = "rat/modules/latlisten.(*latlistensrv).handleCmd" fullword
		$rat7 = "rat/modules/netsweeper.(*netsweeperRunner).runSweep" fullword
		$rat8 = "rat/modules/netsweeper.(*Pinger).listen" fullword
		$rat9 = "rat/modules/socks.(*HTTPProxyClient).beacon" fullword
		$rat10 = "rat/platforms/win/dyloader.(*memoryLoader).ExecutePluginFunction" fullword
		$rat11 = "rat/platforms/win/modules/namedpipe.(*dummy).Open" fullword
		$winblows = "rat/platforms/win.(*winblows).GetStage" fullword

	condition:
		$winblows or 3 of ( $rat* )
}
rule SIGNATURE_BASE_Malware_Sakula_Memory {
    meta:
		description = "Sakula malware - strings after unpacking (memory rule)"
		author = "David Cannings"
		id = "328e3707-d11d-5b7f-bec4-18a42a2c658b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/apt_sakula.yar#L20-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		hash = "b3852b9e7f2b8954be447121bb6b65c3"
		logic_hash = "ba6d93a1fc5fd81748eb462fc55b681987126ba853ddb677a5f1f9b74ba5cde8"
		score = 75
		quality = 85
		tags = ""

	strings:
		$str01 = "cmd.exe /c ping 127.0.0.1 & del \"%s\""
		$str02 = "cmd.exe /c rundll32 \"%s\" Play \"%s\""
		$str03 = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+5.1;+SV1)"
		$str04 = "cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c \"%s\""
		$str05 = "Self Process Id:%d"
		$str06 = "%d_%d_%d_%s"
		$str07 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"
		$str08 = "cmd.exe /c rundll32 \"%s\" ActiveQvaw \"%s\""
		$opcodes01 = { 83 F9 00 74 0E 31 C0 8A 03 D0 C0 34 ?? 88 03 49 43 EB ED }
		$opcodes02 = { 31 C0 8A 04 13 32 01 83 F8 00 75 0E 83 FA 00 74 04 49 4A }

	condition:
		4 of them
}
rule SIGNATURE_BASE_Hvs_APT27_Hyperbro_Stage3_C2 {
    meta:
		description = "HyperBro Stage 3 C2 path and user agent detection - also tested in memory"
		author = "Marc Stroebel"
		id = "d1fe03b9-440c-5127-9572-dddcd5c9966b"
		date = "2022-02-07"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/apt_apt27_hyperbro.yar#L86-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "676df1eaa782c6b876df138a0ddddc3c63e277b84d4414b044314ee219674420"
		score = 50
		quality = 81
		tags = ""
		hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"

	strings:
		$s1 = "api/v2/ajax" ascii wide nocase
		$s2 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36" ascii wide nocase

	condition:
		all of them
}
rule SIGNATURE_BASE_Pos_Malware_Malumpos {
    meta:
		description = "Used to detect MalumPOS memory dumper"
		author = "Trend Micro, Inc."
		id = "6d85c7fe-bf1b-53fb-b618-4b0f8b63cae4"
		date = "2015-05-25"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/crime_malumpos.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "ece32e51a12adf0d68420c8d98efbe7df27b9061ddfe4dcedf151f9f06287eee"
		score = 75
		quality = 60
		tags = ""
		sample_filtype = "exe"

	strings:
		$string1 = "SOFTWARE\\Borland\\Delphi\\RTL"
		$string2 = "B)[0-9]{13,19}\\"
		$string3 = "[A-Za-z\\s]{0,30}\\/[A-Za-z\\s]{0,30}\\"
		$string4 = "TRegExpr(exec): ExecNext Without Exec[Pos]"
		$string5 = /Y:\\PROGRAMS\\.{20,300}\.pas/

	condition:
		all of ( $string* )
}
rule SIGNATURE_BASE_Opcloudhopper_Wmidll_Inmemory {
    meta:
		description = "Malware related to Operation Cloud Hopper - Page 25"
		author = "Florian Roth (Nextron Systems)"
		id = "0afb6e52-bc9a-5a68-890b-79a017e5d554"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/apt_op_cloudhopper.yar#L281-L293"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "6dddda4e519eeaa67eb4c21151cab10553420a23a077751e0fc45fcae0bf6e69"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "wmi.dll 2>&1" ascii

	condition:
		all of them
}
rule SIGNATURE_BASE_HKTL_Cobaltstrike_Beacon_Strings {
    meta:
		description = "Identifies strings used in Cobalt Strike Beacon DLL"
		author = "Elastic"
		id = "af558aa2-a3dc-5a7a-bc74-42bb2246091c"
		date = "2021-03-16"
		modified = "2023-12-05"
		reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/apt_cobaltstrike.yar#L54-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "4349a7ad94df2269217b55c2aef9628c4eef078566c276936accdd4f996ba2cf"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "%02d/%02d/%02d %02d:%02d:%02d"
		$s2 = "Started service %s on %s"
		$s3 = "%s as %s\\%s: %d"

	condition:
		2 of them
}
rule SIGNATURE_BASE_HKTL_Cobaltstrike_Beacon_XOR_Strings {
    meta:
		description = "Identifies XOR'd strings used in Cobalt Strike Beacon DLL"
		author = "Elastic"
		id = "359160a8-cf1c-58a8-bf7f-c09a8d661308"
		date = "2021-03-16"
		modified = "2023-12-05"
		reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/apt_cobaltstrike.yar#L69-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "b5009c29055784ce6371100417b862f723d7e3c1b4081c563fcd8770db48051f"
		score = 75
		quality = 85
		tags = ""
		xor_s1 = "%02d/%02d/%02d %02d:%02d:%02d"
		xor_s2 = "Started service %s on %s"
		xor_s3 = "%s as %s\\%s: %d"

	strings:
		$s1 = "%02d/%02d/%02d %02d:%02d:%02d" xor(0x01-0xff)
		$s2 = "Started service %s on %s" xor(0x01-0xff)
		$s3 = "%s as %s\\%s: %d" xor(0x01-0xff)
		$fp1 = "MalwareRemovalTool"

	condition:
		2 of ( $s* ) and not 1 of ( $fp* )
}
rule SIGNATURE_BASE_HKTL_Cobaltstrike_Beacon_4_2_Decrypt {
    meta:
		description = "Identifies deobfuscation routine used in Cobalt Strike Beacon DLL version 4.2"
		author = "Elastic"
		id = "63b71eef-0af5-5765-b957-ccdc9dde053b"
		date = "2021-03-16"
		modified = "2023-12-05"
		reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/apt_cobaltstrike.yar#L90-L102"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "8685b1626c8d263f49ccf129dcd4fe1b42482fcdb37c2e109cedcecaed8c2407"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
		$a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}

	condition:
		any of them
}
rule SIGNATURE_BASE_WCE_In_Memory {
    meta:
		description = "Detects Windows Credential Editor (WCE) in memory (and also on disk)"
		author = "Florian Roth (Nextron Systems)"
		id = "90c90ca5-e3be-5035-b35c-c2e7faec43a5"
		date = "2016-08-28"
		modified = "2025-04-14"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/yara/thor-hacktools.yar#L3265-L3279"
		license_url = "https://github.com/Neo23x0/signature-base/blob/b896ce978ae3afbe048fc3e60ebe98da84098f10/LICENSE"
		logic_hash = "74ab7772db5b1de8a4eae03370e2be3cd35004730f84d472677688109a1d6d88"
		score = 80
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "wkKUSvflehHr::o:t:s:c:i:d:a:g:" fullword ascii
		$s2 = "wceaux.dll" fullword ascii

	condition:
		all of them
}
