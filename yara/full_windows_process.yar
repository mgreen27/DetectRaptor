rule FIREEYE_RT_APT_Backdoor_Win_Gorat_Memory {
    meta:
		description = "Identifies GoRat malware in memory based on strings."
		author = "FireEye"
		id = "16fb1db7-711c-5d8d-9203-738c94f253fe"
		date = "2020-12-08"
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
rule JPCERTCC_Tscookie {
    meta:
		description = "detect TSCookie in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "5407a5c9-2fc5-5b9b-977f-81384a343d15"
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
rule JPCERTCC_Emotet {
    meta:
		description = "detect Emotet in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "f1cb5e3e-069d-54bb-829d-2ff4aa80e2bb"
		date = "2019-04-22"
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
rule JPCERTCC_Smokeloader {
    meta:
		description = "detect SmokeLoader in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "19666821-1fe9-50e7-958e-22f2260099aa"
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
rule JPCERTCC_Azorult {
    meta:
		description = "detect Azorult in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "c73a007c-4d5f-5504-9635-9bffe1282aef"
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
rule JPCERTCC_Formbook {
    meta:
		description = "detect Formbook in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "71291f9b-eb8e-55e5-a499-df54c35efdbf"
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
rule JPCERTCC_Remcos {
    meta:
		description = "detect Remcos in memory"
		author = "JPCERT/CC Incident Response Group"
		id = "4a27a16a-2669-5009-bc82-082ec0c9b2c1"
		date = "2019-04-22"
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
		date = "2019-04-22"
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
		date = "2019-04-22"
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
rule DITEKSHEN_MALWARE_Win_Quilclipper {
    meta:
		description = "Detects QuilClipper variants mostly in memory or extracted AutoIt script"
		author = "ditekSHen"
		id = "bd23ec5a-f21a-5133-a77a-de2615933b82"
		date = "2020-11-06"
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
		date = "2020-11-06"
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
		modified = "2025-10-21"
		reference = "TRR240501"
		source_url = "https://github.com/HarfangLab/iocs/blob/1770ec1114cc8c83eea7d0ab8f9f29c267b11a2d/hl_public_reports_master.yar#L96-L114"
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
		modified = "2025-10-21"
		reference = "TRR240501"
		source_url = "https://github.com/HarfangLab/iocs/blob/1770ec1114cc8c83eea7d0ab8f9f29c267b11a2d/hl_public_reports_master.yar#L115-L137"
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
		modified = "2025-10-21"
		reference = "TRR250201"
		source_url = "https://github.com/HarfangLab/iocs/blob/1770ec1114cc8c83eea7d0ab8f9f29c267b11a2d/hl_public_reports_master.yar#L276-L294"
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
		source_url = "https://github.com/SEKOIA-IO/Community/blob/a92ecc9714a549f152ac9acae011dcc84dc526af/yara_rules/apt_unk_hrserv_memory_commands_strings.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/a92ecc9714a549f152ac9acae011dcc84dc526af/LICENSE.md"
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
rule SIGNATURE_BASE_Opcloudhopper_Wmidll_Inmemory {
    meta:
		description = "Malware related to Operation Cloud Hopper - Page 25"
		author = "Florian Roth (Nextron Systems)"
		id = "0afb6e52-bc9a-5a68-890b-79a017e5d554"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/apt_op_cloudhopper.yar#L281-L293"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
rule SIGNATURE_BASE_Mimikatz_Memory_Rule_1 : APT {
    meta:
		description = "Detects password dumper mimikatz in memory (False Positives: an service that could have copied a Mimikatz executable, AV signatures)"
		author = "Florian Roth"
		id = "55cc7129-5ea0-5545-a8f6-b5306a014dd0"
		date = "2014-12-22"
		modified = "2023-07-04"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/gen_mimikatz.yar#L5-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/gen_mimikatz.yar#L178-L190"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/gen_mimikatz.yar#L192-L216"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
rule SIGNATURE_BASE_APT_Backdoor_Win_Gorat_Memory_1 {
    meta:
		description = "Identifies GoRat malware in memory based on strings."
		author = "FireEye"
		id = "4fcdd98f-1873-58e1-a9f5-73ee0aa5a69f"
		date = "2020-12-08"
		modified = "2025-02-12"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/gen_fireeye_redteam_tools.yar#L1013-L1039"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
rule SIGNATURE_BASE_HKTL_Cobaltstrike_Beacon_Strings {
    meta:
		description = "Identifies strings used in Cobalt Strike Beacon DLL"
		author = "Elastic"
		id = "af558aa2-a3dc-5a7a-bc74-42bb2246091c"
		date = "2021-03-16"
		modified = "2023-12-05"
		reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/apt_cobaltstrike.yar#L54-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/apt_cobaltstrike.yar#L69-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/apt_cobaltstrike.yar#L90-L102"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
rule SIGNATURE_BASE_Hvs_APT27_Hyperbro_Stage3_C2 {
    meta:
		description = "HyperBro Stage 3 C2 path and user agent detection - also tested in memory"
		author = "Marc Stroebel"
		id = "d1fe03b9-440c-5127-9572-dddcd5c9966b"
		date = "2022-02-07"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/apt_apt27_hyperbro.yar#L86-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
rule SIGNATURE_BASE_APT_Dropper_Raw64_TEARDROP_1 {
    meta:
		description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
		author = "FireEye"
		id = "88adad58-ba16-5996-9ea8-ea356c3ed5b2"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/apt_solarwinds_sunburst.yar#L141-L156"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
rule SIGNATURE_BASE_EXPL_React_Server_CVE_2025_55182_POC_Dec25 : CVE_2025_55182 {
    meta:
		description = "Detects in-memory webshell indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182)"
		author = "Florian Roth"
		id = "6ce94e2d-64bf-5b1c-8f9a-1a22470cad76"
		date = "2025-12-05"
		modified = "2025-12-12"
		reference = "https://x.com/pyn3rd/status/1996840827897954542/photo/1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/react_pocs_indicators_dec25.yar#L1-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
		logic_hash = "a4f27fc85807e8f94e6947523a09d87ceed0658334756a9724322181c3eecd20"
		score = 70
		quality = 85
		tags = "CVE-2025-55182"

	strings:
		$xs1 = "{const cmd=p.query.cmd;if(!cmd)(s.writeHead(400);"
		$s1 = ";if(p.pathname=="
		$s2 = ".writeHead(400);"
		$s3 = ".writeHead(200,{'Content-Type':"
		$s4 = ".execSync("
		$s5 = ",stdio:'pipe'})"

	condition:
		1 of ( $x* ) or all of ( $s* )
}
rule SIGNATURE_BASE_Malware_Sakula_Memory {
    meta:
		description = "Sakula malware - strings after unpacking (memory rule)"
		author = "David Cannings"
		id = "328e3707-d11d-5b7f-bec4-18a42a2c658b"
		date = "2016-06-13"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/apt_sakula.yar#L20-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
rule SIGNATURE_BASE_WCE_In_Memory {
    meta:
		description = "Detects Windows Credential Editor (WCE) in memory (and also on disk)"
		author = "Florian Roth (Nextron Systems)"
		id = "90c90ca5-e3be-5035-b35c-c2e7faec43a5"
		date = "2016-08-28"
		modified = "2025-12-18"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/thor-hacktools.yar#L3256-L3270"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
rule SIGNATURE_BASE_APT_MAL_RU_WIN_Snake_Malware_May23_1 : MEMORY {
    meta:
		description = "Hunting Russian Intelligence Snake Malware"
		author = "Matt Suiche (Magnet Forensics)"
		id = "53d2de3c-350c-5090-84bb-b6cde16a80ad"
		date = "2023-05-10"
		modified = "2025-03-21"
		reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/apt_mal_ru_snake_may23.yar#L17-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
rule SIGNATURE_BASE_Pos_Malware_Malumpos {
    meta:
		description = "Used to detect MalumPOS memory dumper"
		author = "Trend Micro, Inc."
		id = "6d85c7fe-bf1b-53fb-b618-4b0f8b63cae4"
		date = "2015-05-25"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/crime_malumpos.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
rule SIGNATURE_BASE_Fidelis_Advisory_Cedt370 {
    meta:
		description = "Detects a string found in memory of malware cedt370r(3).exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b5ebf2d7-e3e4-5b3b-a082-417da9c7fda6"
		date = "2015-06-09"
		modified = "2023-12-05"
		reference = "http://goo.gl/ZjJyti"
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/apt_fidelis_phishing_plain_sight.yar#L16-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
		source_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/yara/gen_metasploit_payloads.yar#L341-L363"
		license_url = "https://github.com/Neo23x0/signature-base/blob/42eae6fef41552e3faa3b3f82166ff4eecba9146/LICENSE"
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
