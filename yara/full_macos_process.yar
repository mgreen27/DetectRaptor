rule BINARYALERT_Hacktool_Macos_Macpmem {
    meta:
		description = "MacPmem enables read/write access to physical memory on macOS. Can be used by CSIRT teams and attackers."
		author = "@mimeframe"
		id = "4890598e-936c-5a4d-9004-88ff4fe57c49"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/google/rekall/tree/master/tools/osx/MacPmem"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_macpmem.yara#L3-L22"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "d64b5a5423932211e3b72d949028f3f0ed1f1435e9584cffa947f2bd4846c29b"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "%s/MacPmem.kext" wide ascii
		$a2 = "The Pmem physical memory imager." wide ascii
		$a3 = "The OSXPmem memory imager." wide ascii
		$a4 = "These AFF4 Volumes will be loaded and their metadata will be parsed before the program runs." wide ascii
		$a5 = "Pmem driver version incompatible. Reported" wide ascii
		$a6 = "Memory access driver left loaded since you specified the -l flag." wide ascii
		$b1 = "Unloading MacPmem" wide ascii
		$b2 = "MacPmem load tag is" wide ascii

	condition:
		BINARYALERT_Macho_PRIVATE and 2 of ( $a* ) or all of ( $b* )
}
rule VOLEXITY_Susp_Any_Jarischf_User_Path : FILE MEMORY {
    meta:
		description = "Detects paths embedded in samples in released projects written by Ferdinand Jarisch, a pentester in AISEC. These tools are sometimes used by attackers in real world intrusions."
		author = "threatintel@volexity.com"
		id = "062a6fdb-c516-5643-9c7c-deff32eeb95e"
		date = "2024-04-10"
		modified = "2024-04-15"
		reference = "TIB-20240412"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L59-L81"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L82-L116"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
rule VOLEXITY_Apt_Malware_Macos_Vpnclient_Cc_Oct23 : CHARMINGCYPRESS FILE MEMORY {
    meta:
		description = "Detection for fake macOS VPN client used by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "e0957936-dc6e-5de6-bb23-d0ef61655029"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-02-13 CharmingCypress/rules.yar#L246-L272"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
		logic_hash = "da5e9be752648b072a9aaeed884b8e1729a14841e33ed6633a0aaae1f11bd139"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "11f0e38d9cf6e78f32fb2d3376badd47189b5c4456937cf382b8a574dc0d262d"
		os = "darwin,linux"
		os_arch = "all"
		parent_hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9770
		version = 3

	strings:
		$s1 = "networksetup -setsocksfirewallproxystate wi-fi off" ascii
		$s2 = "networksetup -setsocksfirewallproxy wi-fi ___serverAdd___ ___portNum___; networksetup -setsocksfirewallproxystate wi-fi on" ascii
		$s3 = "New file imported successfully." ascii
		$s4 = "Error in importing the File." ascii

	condition:
		2 of ( $s* )
}
rule VOLEXITY_Malware_Golang_Discordc2_Bmdyy_1 : FILE MEMORY {
    meta:
		description = "Detects a opensource malware available on github using strings in the binary. The DISGOMOJI malware family used by TransparentJasmine is based on this malware."
		author = "threatintel@volexity.com"
		id = "6816d264-4311-5e90-948b-2e27cdf0b720"
		date = "2024-03-28"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L216-L243"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L244-L267"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
rule VOLEXITY_Apt_Malware_Any_Reloadext_Plugin : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detection for RELOADEXT, a Google Chrome extension malware."
		author = "threatintel@volexity.com"
		id = "6c6c8bee-2a13-5645-89ef-779f00264fd9"
		date = "2024-02-23"
		modified = "2024-08-02"
		reference = "TIB-20240227"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-08-02 StormBamboo/rules.yar#L4-L36"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
rule VOLEXITY_Apt_Malware_Macos_Reloadext_Installer : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detect the RELOADEXT installer."
		author = "threatintel@volexity.com"
		id = "c65ea2b5-ab98-5693-92ea-05c0f1ea1e5b"
		date = "2024-02-23"
		modified = "2024-08-02"
		reference = "TIB-20240227"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-08-02 StormBamboo/rules.yar#L37-L62"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
		logic_hash = "8688796839202d95ded15e10262a7a7c7cbbae4a332b60305402e5984005d452"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "07e3b067dc5e5de377ce4a5eff3ccd4e6a2f1d7a47c23fe06b1ededa7aed1ab3"
		os = "darwin"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10281
		version = 2

	strings:
		$str1 = "/CustomPlug1n/"
		$str2 = "Chrome NOT installed."
		$str3 = "-f force kill Chrome"
		$str4 = "/*} &&cp -rf ${"

	condition:
		3 of them
}
rule VOLEXITY_Apt_Malware_Any_Macma_A : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detects variants of the MACMA backdoor, variants of MACMA have been discovered for macOS and android."
		author = "threatintel@volexity.com"
		id = "6ab45af1-41e5-53fc-9297-e2bc07ebf797"
		date = "2021-11-12"
		modified = "2024-08-02"
		reference = "https://blog.google/threat-analysis-group/analyzing-watering-hole-campaign-using-macos-exploits/"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-08-02 StormBamboo/rules.yar#L63-L111"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
rule VOLEXITY_Apt_Malware_Macos_Gimmick : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detects the macOS port of the GIMMICK malware."
		author = "threatintel@volexity.com"
		id = "3d485788-4aab-511b-a49e-5dc09d1950a9"
		date = "2021-10-18"
		modified = "2024-08-02"
		reference = "https://www.volexity.com/blog/2022/03/22/storm-cloud-on-the-horizon-gimmick-malware-strikes-at-macos/"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-08-02 StormBamboo/rules.yar#L112-L170"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
		logic_hash = "00fba9df2212874a45d44b3d098a7b76c97fcd53ff083c76b784d2b510a4a467"
		score = 75
		quality = 78
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
		os = "darwin"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6022
		version = 8

	strings:
		$s1 = "http://cgi1.apnic.net/cgi-bin/my-ip.php --connect-timeout 10 -m 20" wide ascii
		$json1 = "base_json" ascii wide
		$json2 = "down_json" ascii wide
		$json3 = "upload_json" ascii wide
		$json4 = "termin_json" ascii wide
		$json5 = "request_json" ascii wide
		$json6 = "online_json" ascii wide
		$json7 = "work_json" ascii wide
		$msg1 = "bash_pid: %d, FDS_CHILD: %d, FDS_PARENT: %d" ascii wide
		$msg2 = "pid %d is dead" ascii wide
		$msg3 = "exit with code %d" ascii wide
		$msg4 = "recv signal %d" ascii wide
		$cmd1 = "ReadCmdQueue" ascii wide
		$cmd2 = "read_cmd_server_timer" ascii wide
		$cmd3 = "enableProxys" ascii wide
		$cmd4 = "result_block" ascii wide
		$cmd5 = "createDirLock" ascii wide
		$cmd6 = "proxyLock" ascii wide
		$cmd7 = "createDirTmpItem" ascii wide
		$cmd8 = "dowfileLock" ascii wide
		$cmd9 = "downFileTmpItem" ascii wide
		$cmd10 = "filePathTmpItem" ascii wide
		$cmd11 = "uploadItems" ascii wide
		$cmd12 = "downItems" ascii wide
		$cmd13 = "failUploadItems" ascii wide
		$cmd14 = "failDownItems" ascii wide
		$cmd15 = "downloadCmds" ascii wide
		$cmd16 = "uploadFiles" ascii wide
		$cmd17 = "bash callback...." ascii wide

	condition:
		$s1 or 5 of ( $json* ) or 3 of ( $msg* ) or 9 of ( $cmd* )
}
rule VOLEXITY_Apt_Malware_Py_Dustpan_Pyloader : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detects Python script used by KPlayer to update, modified by attackers to download a malicious payload."
		author = "threatintel@volexity.com"
		id = "446d2eef-c60a-50ed-9ff1-df86b6210dff"
		date = "2023-07-21"
		modified = "2024-08-02"
		reference = "TIB-20231221"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-08-02 StormBamboo/rules.yar#L236-L270"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
rule VOLEXITY_Hacktool_Py_Pysoxy : FILE MEMORY {
    meta:
		description = "SOCKS5 proxy tool used to relay connections."
		author = "threatintel@volexity.com"
		id = "88094b55-784d-5245-9c40-b1eebf0e6e72"
		date = "2024-01-09"
		modified = "2024-01-09"
		reference = "TIB-20240109"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L87-L114"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
rule VOLEXITY_Apt_Malware_Js_Sharpext : SHARPPINE FILE MEMORY {
    meta:
		description = "A malicious Chrome browser extension used by the SharpPine threat actor to steal Gmail data from a victim."
		author = "threatintel@volexity.com"
		id = "61b5176a-ff73-5fce-bc70-c9e09bb5afed"
		date = "2021-09-14"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2022/2022-07-28 SharpTongue SharpTongue Deploys Clever Mail-Stealing Browser Extension SHARPEXT/yara.yar#L1-L52"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
rule VOLEXITY_Webshell_Jsp_Converge : FILE MEMORY CVE_2022_26134 {
    meta:
		description = "Detects CONVERGE - a file upload webshell observed in incident involving compromise of Confluence server via CVE-2022-26134."
		author = "threatintel@volexity.com"
		id = "2a74678e-cb00-567c-a2e0-2e095f3e5ee8"
		date = "2022-06-01"
		modified = "2024-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L1-L21"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L61-L84"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
rule VOLEXITY_Malware_Golang_Pantegana : FILE MEMORY {
    meta:
		description = "Detects PANTEGANA, a Golang backdoor used by a range of threat actors due to its public availability."
		author = "threatintel@volexity.com"
		id = "b6154165-68e0-5986-a0cf-5631d369c230"
		date = "2022-03-30"
		modified = "2025-03-21"
		reference = "https://github.com/elleven11/pantegana"
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L90-L120"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
		source_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L121-L158"
		license_url = "https://github.com/volexity/threat-intel/blob/c24b8d9bea44ac757193a3152b1fd9dbf34fe503/LICENSE.txt"
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
