rule VOLEXITY_Apt_Malware_Macos_Vpnclient_Cc_Oct23 : CHARMINGCYPRESS FILE MEMORY {
    meta:
		description = "Detection for fake macOS VPN client used by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "e0957936-dc6e-5de6-bb23-d0ef61655029"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-02-13 CharmingCypress/rules.yar#L246-L272"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "11f0e38d9cf6e78f32fb2d3376badd47189b5c4456937cf382b8a574dc0d262d"
		hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
		logic_hash = "da5e9be752648b072a9aaeed884b8e1729a14841e33ed6633a0aaae1f11bd139"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		os = "darwin,linux"
		os_arch = "all"
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
rule VOLEXITY_Apt_Malware_Py_Upstyle : UTA0218 FILE MEMORY {
    meta:
		description = "Detect the UPSTYLE webshell."
		author = "threatintel@volexity.com"
		id = "45726f35-8b3e-5095-b145-9e7f6da6838b"
		date = "2024-04-11"
		modified = "2024-04-12"
		reference = "TIB-20240412"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L1-L34"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"
		hash = "0d59d7bddac6c22230187ef6cf7fa22bca93759edc6f9127c41dc28a2cea19d8"
		hash = "4dd4bd027f060f325bf6a90d01bfcf4e7751a3775ad0246beacc6eb2bad5ec6f"
		logic_hash = "51923600b23d23f4ce29eac7f5ab9f7e1ddb45bed5f6727ddec4dcb75872e473"
		score = 75
		quality = 80
		tags = "UTA0218, FILE, MEMORY"
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
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L59-L81"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
		logic_hash = "574d5b1fadb91c39251600e7d73d4993d4b16565bd1427a0e8d6ed4e7905ab54"
		score = 50
		quality = 80
		tags = "FILE, MEMORY"
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
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L82-L116"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
		logic_hash = "38b40cc7fc1e601da2c7a825f1c2eff209093875a5829ddd2f4c5ad438d660f8"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
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
rule VOLEXITY_Apt_Webshell_Pl_Complyshell : UTA0178 FILE MEMORY {
    meta:
		description = "Detection for the COMPLYSHELL webshell."
		author = "threatintel@volexity.com"
		id = "6b44b5bc-a75f-573c-b9c3-562b7874e408"
		date = "2023-12-13"
		modified = "2024-01-12"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L3-L25"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "8bc8f4da98ee05c9d403d2cb76097818de0b524d90bea8ed846615e42cb031d2"
		logic_hash = "ff46691f1add20cff30fe996e2fb199ce42408e86d5642a8a43c430f2245b1f5"
		score = 75
		quality = 80
		tags = "UTA0178, FILE, MEMORY"
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
rule VOLEXITY_Hacktool_Py_Pysoxy : FILE MEMORY {
    meta:
		description = "SOCKS5 proxy tool used to relay connections."
		author = "threatintel@volexity.com"
		id = "88094b55-784d-5245-9c40-b1eebf0e6e72"
		date = "2024-01-09"
		modified = "2024-01-09"
		reference = "TIB-20240109"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L87-L114"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "e192932d834292478c9b1032543c53edfc2b252fdf7e27e4c438f4b249544eeb"
		logic_hash = "f73e9d3c2f64c013218469209f3b69fc868efafc151a7de979dde089bfdb24b2"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
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
rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Modules : TRANSPARENTJASMINE FILE MEMORY {
    meta:
		description = "Detects DISGOMOJI modules using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "b9e4ecdc-9b02-546f-9b79-947cb6b1f99a"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L1-L24"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "2abaae4f6794131108adf5b42e09ee5ce24769431a0e154feabe6052cfe70bf3"
		logic_hash = "7880288e3230b688b780bdfbac2b0761fd7831b7df233672c2242c21a86e1297"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10270
		version = 6

	strings:
		$s1 = "discord-c2/test/main/finalizing/Deliveries/ob_Delivery.go" wide ascii
		$s2 = "discord-c2/test/main/finalizing/WAN_Conf.go" wide ascii

	condition:
		any of them
}
rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Loader : TRANSPARENTJASMINE FILE MEMORY {
    meta:
		description = "Detects DISGOMOJI loader using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "6d7848db-f1a5-5ccc-977a-7597b966a31c"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L25-L47"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "51a372fee89f885741515fa6fdf0ebce860f98145c9883f2e3e35c0fe4432885"
		logic_hash = "d9be4846bab5fffcfd60eaec377443819404f30ec088905c2ee26bd3b7525832"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10269
		version = 7

	strings:
		$s1 = "discord-c2/test/main/delievery.go" wide ascii

	condition:
		$s1
}
rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Debug_String : TRANSPARENTJASMINE FILE MEMORY {
    meta:
		description = "Detects DISGOMOJI using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "eed2468f-7e50-5f3e-946a-277c10984823"
		date = "2024-02-22"
		modified = "2024-11-27"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L48-L71"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		logic_hash = "6bb130eead39bd8128983e0f2e76cfeff8865ce8ed3cb73b132ed32d68fc0db0"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10268
		version = 9

	strings:
		$s1 = "discord-c2/test/main/payload.go" wide ascii
		$s2 = "Desktop/Golang_Dev/Discord"

	condition:
		any of them
}
rule VOLEXITY_Apt_Malware_Linux_Disgomoji_2 : TRANSPARENTJASMINE FILE MEMORY {
    meta:
		description = "Detects DISGOMOJI malware using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "609beb47-5e93-5f69-b89d-2cf62f20851a"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L72-L103"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		logic_hash = "e03a774cca2946c1becdbd775ef465033dae089d578ea18a4f43fd7bdae9168e"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10266
		version = 9

	strings:
		$s1 = "downloadFileFromURL" wide ascii
		$s2 = "createCronJob" wide ascii
		$s3 = "findAndSendFiles" wide ascii
		$s4 = "updateLogFile" wide ascii
		$s5 = "handleZipFile" wide ascii
		$s6 = "takeScreenshot" wide ascii
		$s7 = "zipFirefoxProfile" wide ascii
		$s8 = "zipDirectoryWithParts" wide ascii
		$s9 = "uploadAndSendToOshi" wide ascii
		$s10 = "uploadAndSendToLeft" wide ascii

	condition:
		7 of them
}
rule VOLEXITY_Apt_Malware_Linux_Disgomoji_1 : TRANSPARENTJASMINE FILE MEMORY {
    meta:
		description = "Detects GOMOJI malware using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "f6643e9a-ca41-57e0-9fce-571d340f1cfe"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L104-L131"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		logic_hash = "dd3535079881ae9cfe25c129803668cb595be89b7f62eb82af19cc3839f92b6d"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10265
		version = 7

	strings:
		$s1 = "Session *%s* opened!" wide ascii
		$s2 = "uevent_seqnum.sh" wide ascii
		$s3 = "Error downloading shell script: %v" wide ascii
		$s4 = "Error setting execute permissions: %v" wide ascii
		$s5 = "Error executing shell script: %v" wide ascii
		$s6 = "Error creating Discord session" wide ascii

	condition:
		4 of them
}
rule VOLEXITY_Malware_Golang_Discordc2_Bmdyy_1 : FILE MEMORY {
    meta:
		description = "Detects a opensource malware available on github using strings in the binary. The DISGOMOJI malware family used by TransparentJasmine is based on this malware."
		author = "threatintel@volexity.com"
		id = "6816d264-4311-5e90-948b-2e27cdf0b720"
		date = "2024-03-28"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L216-L243"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "de32e96d1f151cc787841c12fad88d0a2276a93d202fc19f93631462512fffaf"
		logic_hash = "22b3e5109d0738552fbc310344b2651ab3297e324bc883d5332c1e8a7a1df29b"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
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
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L244-L267"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		logic_hash = "38b860a43b9937351f74b01983888f18ad101cbe66560feb7455d46b713eba0f"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
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
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-08-02 StormBamboo/rules.yar#L4-L36"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "9d0928b3cc21ee5e1f2868f692421165f46b5014a901636c2a2b32a4c500f761"
		logic_hash = "2b11f8fc5b6260ebf00bde83585cd7469709a4979ca579cdf065724bc15052fc"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
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
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-08-02 StormBamboo/rules.yar#L63-L111"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"
		hash = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
		hash = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
		hash = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
		logic_hash = "7ebaff9fddf6491d6b1ed9ab14c1b87dc8df850536e55aa723d625a593b33ed7"
		score = 75
		quality = 53
		tags = "STORMBAMBOO, FILE, MEMORY"
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
rule VOLEXITY_Apt_Malware_Py_Dustpan_Pyloader : STORMBAMBOO FILE MEMORY {
    meta:
		description = "Detects Python script used by KPlayer to update, modified by attackers to download a malicious payload."
		author = "threatintel@volexity.com"
		id = "446d2eef-c60a-50ed-9ff1-df86b6210dff"
		date = "2023-07-21"
		modified = "2024-08-02"
		reference = "TIB-20231221"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-08-02 StormBamboo/rules.yar#L236-L270"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
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
rule VOLEXITY_Apt_Malware_Elf_Catchdns_Aug20_Memory : DRIFTINGBAMBOO FILE MEMORY {
    meta:
		description = "Looks for strings from CatchDNS component used to intercept and modify DNS responses, and likely also intercept/monitor http. This rule would only match against memory in the example file analyzed by Volexity."
		author = "threatintel@volexity.com"
		id = "933b7585-1b1c-5d25-a599-078a0b0d0077"
		date = "2020-08-20"
		modified = "2025-06-19"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2024/2024-08-02 StormBamboo/rules.yar#L309-L383"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "4f3d35f4f8b810362cbd4c59bfe5a961e559fe5713c9478294ccb3af2d306515"
		logic_hash = "241fd5884b27269b9b07b891fb9e226c33c468276df796f91af98a68765a8b0d"
		score = 75
		quality = 55
		tags = "DRIFTINGBAMBOO, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		report1 = "MAR-20221222"
		report2 = "TIB-20231221"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 227
		version = 11

	strings:
		$os1 = "current thread policy=%d" ascii wide
		$os2 = "OS_CreatShareMem %s-->%x" ascii wide
		$os3 = "sem_open fail" ascii wide
		$os4 = "int OS_GetCurRunPath(char*, int)" ascii wide
		$os5 = "int OS_GetCurModName(char*, int)" ascii wide
		$os6 = "int OS_StrToTime(char*, time_t*)" ascii wide
		$os7 = "int OS_TimeToStr(time_t, char*)" ascii wide
		$os8 = "int OS_TimeToStrYearMothDay(time_t, char*)" ascii wide
		$os9 = "bool OS_Access(const char*)" ascii wide
		$os10 = "int OS_Memicmp(const void*, const void*, unsigned int)" ascii wide
		$os11 = "int OS_Mkdir(char*)" ascii wide
		$os12 = "OS_ConnectSem" ascii wide
		$msg1 = "client: last send packet iseq: %x, the ack :%x" ascii wide
		$msg2 = "server: last send packet iseq: %x, the iseq :%x" ascii wide
		$msg3 = "send packet failed!" ascii wide
		$msg4 = "will hijack dns:%s, ip:%s " ascii wide
		$msg5 = "dns send ok:%s" ascii wide
		$msg6 = "tcp send ok" ascii wide
		$msg7 = "FilePath:%s;" ascii wide
		$msg8 = "Line:%d,Fun:%s,ErrorCode:%u;" ascii wide
		$msg9 = "Description:%s;" ascii wide
		$msg10 = "Line:%d,Fun:%s,ErrorCode:%u;" ascii wide
		$msg11 = "get msg from ini is error" ascii wide
		$msg12 = "on build eth send_msg or payload is null" ascii wide
		$msg13 = "on build udp send_msg or payload is null" ascii wide
		$conf1 = "%d.%d.%d.%d" ascii wide
		$conf2 = "%s.tty" ascii wide
		$conf3 = "dns.ini" ascii wide
		$netw1 = "LISTEN_DEV" ascii wide
		$netw2 = "SEND_DEV" ascii wide
		$netw3 = "SERVER_IP" ascii wide
		$netw4 = "DNSDomain" ascii wide
		$netw5 = "IpLimit" ascii wide
		$netw6 = "HttpConfig" ascii wide
		$netw7 = "buildhead" ascii wide
		$netw8 = "sendlimit" ascii wide
		$netw9 = "content-type" ascii wide
		$netw10 = "otherhead_" ascii wide
		$netw11 = "configfile" ascii wide
		$apache = "HTTP/1.1 200 OK\x0d\nServer: Apache\x0d\nConnection: close\x0d\nContent-Type: %s\x0d\nContent-Length: %d\x0d\n"
		$cpp1 = "src/os.cpp"
		$cpp2 = "src/test_catch_dns.cpp"

	condition:
		9 of ( $os* ) or 3 of ( $msg* ) or all of ( $conf* ) or all of ( $netw* ) or $apache or all of ( $cpp* )
}
rule VOLEXITY_Apt_Malware_Any_Dotnet_Aot_Plenet : VERDANTBAMBOO PLENET FILE MEMORY {
    meta:
		description = "Detect PLENET, a multiplatform malware compile with native AOT."
		author = "threatintel@volexity.com"
		id = "615d7c43-0128-5cfa-a080-6ece5d2dc029"
		date = "2025-09-22"
		modified = "2025-10-30"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2026/2026-06-04 VerdantBamboo/rules.yar#L1-L31"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "eb141a43958802727a6c813452450c10b92704bea4474ee5fd87c0a1be326e2e"
		logic_hash = "67d8f7fbc2986b1068a9c557cf85ba83469e3fb7f2433bd10c7ad740a4b0e717"
		score = 75
		quality = 80
		tags = "VERDANTBAMBOO, PLENET, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		report1 = "TIB-20251104"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 12367
		version = 4

	strings:
		$str1 = "[!] Bad dat" wide
		$str2 = "[!] Connection error. Kill Pty" wide
		$str3 = "[!] Error : Plexor is nul" wide
		$str4 = "[!] Unkown message type" wide
		$str5 = "[*] Disposing.." wide
		$str6 = "Lack port ':" wide
		$str7 = "IPv6 port error ':" wide
		$str8 = "this.existingPipeGiven." wide
		$str9 = "port must within 0~6553" wide

	condition:
		4 of them
}
rule VOLEXITY_Apt_Malware_Elf_Verdantbamboo_Paths : VERDANTBAMBOO FILE MEMORY {
    meta:
		description = "Detection for VerdantBamboo related malware based on paths from local machines observed in binaries."
		author = "threatintel@volexity.com"
		id = "256f6bdc-1067-52e8-81b9-c7be1b802947"
		date = "2025-09-22"
		modified = "2026-01-27"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2026/2026-06-04 VerdantBamboo/rules.yar#L32-L54"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "eb141a43958802727a6c813452450c10b92704bea4474ee5fd87c0a1be326e2e"
		logic_hash = "aac17908a9d5e71d5db3fbdf9bb3307c74f5911bd253bb2060b05fbf238b2c3f"
		score = 75
		quality = 80
		tags = "VERDANTBAMBOO, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		report1 = "TIB-20251104"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 12361
		version = 3

	strings:
		$s1 = "bin/Release/net8.0/linux-x64/native/server" ascii

	condition:
		$s1
}
rule VOLEXITY_Apt_Malware_Golang_Brickstorm_B : VERDANTBAMBOO BRICKSTORM FILE MEMORY {
    meta:
		description = "Detection for the BRICKSTORM malware family."
		author = "threatintel@volexity.com"
		id = "b3b9ff26-56ab-5801-8905-0a304887b998"
		date = "2025-09-05"
		modified = "2026-06-09"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2026/2026-06-04 VerdantBamboo/rules.yar#L56-L98"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "aa688682d44f0c6b0ed7f30b981a609100107f2d414a3a6e5808671b112d1878"
		logic_hash = "e91203a714a4bc9d1c70eae4670681e3f416257163cf44db20ad33380be5d39a"
		score = 75
		quality = 80
		tags = "VERDANTBAMBOO, BRICKSTORM, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		report1 = "TIB-20251104"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 12299
		version = 6

	strings:
		$method1 = "UnPackHeaderData"
		$method2 = "handleRelay"
		$method3 = "NewWebSocketClient"
		$method4 = "createDnsMessage"
		$method5 = "GetFileOwnerInfo"
		$err1 = "dns rcode: %v"
		$err2 = "readFull error"
		$err3 = "tagAuth error"
		$err4 = "error: Auth: %s"
		$ws1 = "<a style='text-decoration: none;'  href='javascript:history.go(-1);'><h5>Back</h5></a>"
		$ws2 = "Mon, 02 Jan 2006 15:04:05 GMT"
		$doh = "https://1.0.0.1/dns-queryhttps://1.1.1.1/dns-queryhttps://8.8.4.4/dns-queryhttps://8.8.8.8/dns-query"

	condition:
		4 of ( $method* ) or 3 of ( $err* ) or all of ( $ws* ) or ( $doh and 3 of ( $method* , $err* , $ws* , $doh ) )
}
rule VOLEXITY_Apt_Malware_Golang_Brickstorm : VERDANTBAMBOO BRICKSTORM FILE MEMORY {
    meta:
		description = "Detects the BRICKSTORM backdoor using common strings."
		author = "threatintel@volexity.com"
		id = "25775278-5115-5873-957f-9c5d0c8e4f5e"
		date = "2025-09-04"
		modified = "2025-10-30"
		reference = "https://blog.nviso.eu/wp-content/uploads/2025/04/NVISO-BRICKSTORM-Report.pdf"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2026/2026-06-04 VerdantBamboo/rules.yar#L100-L136"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "40d264cf9c73923932c3dfd52d20f46ff602be3fea8dc6ecc71aca46e6067bf5"
		hash = "e981fc4eaaa6417e6034e21438e55c0360773674a6fc0b63c1b95026449e5254"
		logic_hash = "39e3403d90ad67072ae631273e89fe059ec48906ce1d57fe1afbb91304dc84f3"
		score = 75
		quality = 80
		tags = "VERDANTBAMBOO, BRICKSTORM, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		report1 = "TIB-20251104"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 12298
		version = 7

	strings:
		$dns1 = "https://1.1.1.1/dns-query" ascii
		$dns2 = "https://8.8.4.4/dns-query" ascii
		$dns3 = "https://8.8.8.8/dns-query" ascii
		$pack1 = "wsshell/core" ascii
		$pack2 = "wssoft/core" ascii
		$s1 = "github.com/hashicorp/yamux" ascii
		$s2 = "winbindd:" ascii
		$s3 = "WEE1=true" ascii
		$s4 = "WEE2=true" ascii

	condition:
		all of ( $dns* ) and all of ( $s* ) and any of ( $pack* )
}
rule VOLEXITY_Apt_Malware_Py_Agentpsd : VERDANTBAMBOO AGENTPSD MEMORY {
    meta:
		description = "Detection for AgentPSD, a python-based malware typically delivered within PyInstaller-built binaries."
		author = "threatintel@volexity.com"
		id = "4a7d531f-926d-557e-b2a0-d4f103e9c63a"
		date = "2025-09-05"
		modified = "2025-10-30"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2026/2026-06-04 VerdantBamboo/rules.yar#L137-L171"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "ee41e06ed96182ce80cd4544a6abd5d7719c4a5c0e5ddb266a83842d39b99b0a"
		logic_hash = "dd0b957bc2a61ddebd392b86b35bae8c1052a285fa31ccd700e580c2ad9cce59"
		score = 75
		quality = 80
		tags = "VERDANTBAMBOO, AGENTPSD, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "memory"
		severity = "critical"
		report1 = "TIB-20251104"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 12297
		version = 5

	strings:
		$s1 = "g_strPhpUrl" ascii
		$s2 = "g_nSleepMinits" ascii
		$s3 = "g_nDuringTime" ascii
		$func1 = "startwork" ascii
		$func2 = "ifrunning" ascii
		$func3 = "getsysinfo" ascii
		$func4 = "getcmdfromweb" ascii
		$func5 = "ParseCmdFromResponse" ascii
		$func6 = "PostDataToServer" ascii
		$func7 = "DealWithBuildinCommand" ascii
		$func8 = "PostBuildinResultToWeb" ascii

	condition:
		2 of ( $s* ) or 4 of ( $func* )
}
rule VOLEXITY_Apt_Webshell_Java_Orangetail_B : UTA0533 ORANGETAIL FILE MEMORY {
    meta:
		description = "Detection for the accept logic of ORANGETAIL, a custom Java webshell used by UTA0533."
		author = "threatintel@volexity.com"
		id = "e9f19175-ea33-5eea-8663-91fc805306bb"
		date = "2026-07-06"
		modified = "2026-07-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2026/2026-07-17 SonicWall/rules.yar#L1-L25"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "1e1e68bbb899450a57274a8b12082ed4e2040a2aae77014f20431689d2b4edee"
		hash = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
		logic_hash = "e5ed25fb820dc4a18c374936c36d4321e2aba72d8b640cdb0d81abd764786918"
		score = 75
		quality = 80
		tags = "UTA0533, ORANGETAIL, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		report1 = "TIB-20260714B"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 13240
		version = 6

	strings:
		$s1 = ".equals($1.getHeader(\"User-Agent\"))) {  javax.servlet.jsp.JspFactory" ascii
		$s2 = " $2.setStatus(404);  $2.setContentLength(0);  $2.flushBuffer();  return;" ascii

	condition:
		all of them
}
rule VOLEXITY_Apt_Webshell_Java_Orangetail : UTA0533 ORANGETAIL FILE MEMORY {
    meta:
		description = "Detection for ORANGETAIL, a custom Java webshell used by UTA0533."
		author = "threatintel@volexity.com"
		id = "5bbffb5f-0917-57e4-a7d4-f5c770b5d253"
		date = "2026-07-06"
		modified = "2026-07-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2026/2026-07-17 SonicWall/rules.yar#L26-L53"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
		logic_hash = "1a495df2bc13b1c2c61315d76d66b150452b923afa5847121429fa8ae9788a7b"
		score = 75
		quality = 80
		tags = "UTA0533, ORANGETAIL, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		report1 = "TIB-20260714B"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 13239
		version = 5

	strings:
		$s1 = "agentmain called args="
		$s2 = "tryInject="
		$s3 = "agentmain ex:"
		$s4 = "javassist="
		$s5 = "tryInject exception"
		$s6 = "found loaded class:"

	condition:
		4 of ( $s* )
}
rule VOLEXITY_Apt_Malware_Any_Uta0533_Ua : UTA0533 FILE MEMORY {
    meta:
		description = "Identify any blob containing a bogus user-agent used in different components of an attack attributed to UTA0533."
		author = "threatintel@volexity.com"
		id = "c13dafb2-b2c3-5988-91dd-0345ef60086c"
		date = "2026-07-06"
		modified = "2026-07-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2026/2026-07-17 SonicWall/rules.yar#L54-L76"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3"
		logic_hash = "d4c0322080e853f5c5d495af05d43eaf3d375af6905e795cef718dec639a7092"
		score = 75
		quality = 80
		tags = "UTA0533, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		report1 = "TIB-20260714B"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 13237
		version = 3

	strings:
		$s1 = "Mozilla/6.0 (Windows NT 11.0; Win64; x64) AppleWebKit/1537.136 (KHTML, like Gecko) Chrome/149.0.0.1 Safari/1537.136" ascii

	condition:
		$s1
}
rule VOLEXITY_Apt_Malware_Python_Knuckleball : UTA0533 KNUCKLEBALL FILE MEMORY {
    meta:
		description = "Detects KNUCKLEBALL, a python based injector malware, using string patterns."
		author = "threatintel@volexity.com"
		id = "bceaee99-902b-5e0d-a8e6-f9909fcd3334"
		date = "2026-07-06"
		modified = "2026-07-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2026/2026-07-17 SonicWall/rules.yar#L77-L109"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3"
		logic_hash = "306b5e0cc66af163c1dea29f8c55f0dbb396ddcefb63f22d62601d7cf1ea839d"
		score = 75
		quality = 80
		tags = "UTA0533, KNUCKLEBALL, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		report1 = "TIB-20260714B"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 13233
		version = 5

	strings:
		$s1 = "/tmp/.java_pid{pid}" ascii
		$s2 = "/tmp/.attach_pid{pid}" ascii
		$s3 = "timeout waiting for JVMTI attach socket" ascii
		$s4 = "workplace.startup.CommandStartup" ascii
		$s5 = "/var/run/control.unit.sock" ascii
		$func1 = "unit_put(" ascii
		$func2 = "check_gate(" ascii
		$func3 = "inject_jar(" ascii
		$func4 = "find_wp_pid(" ascii

	condition:
		2 of ( $s* ) or 3 of ( $func* )
}
rule VOLEXITY_Apt_Malware_Linux_Rootrun : UTA0533 ROOTRUN FILE MEMORY {
    meta:
		description = "Detects rootrun a setuid privilege escalation utility for Linux written in C using strings."
		author = "threatintel@volexity.com"
		id = "cd216f82-9942-5d18-bdb6-d06fa4cf7add"
		date = "2026-07-06"
		modified = "2026-07-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2026/2026-07-17 SonicWall/rules.yar#L110-L134"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "81a9af3846bad3a1107164ff7cf0a08e020b31a3b32fd17866e17d4c1565f7f2"
		logic_hash = "f14483c4a597e6cf66bb36dcfbbe8c87147a37d4c8a30de5738ced670c2a65cd"
		score = 75
		quality = 55
		tags = "UTA0533, ROOTRUN, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 13232
		version = 4

	strings:
		$s1 = "rootrun" ascii
		$s2 = "execlp" ascii
		$s3 = "Usage: rootrun rootrun <command>\n" ascii
		$s4 = "Failed to setuid" ascii

	condition:
		all of them
}
rule VOLEXITY_Webshell_Jsp_Godzilla : FILE MEMORY {
    meta:
		description = "Detects the JSP implementation of the Godzilla Webshell."
		author = "threatintel@volexity.com"
		id = "47c8eab8-84d7-5566-b757-5a6dcc7579b7"
		date = "2021-11-08"
		modified = "2024-07-30"
		reference = "https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L1-L34"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "2786d2dc738529a34ecde10ffeda69b7f40762bf13e7771451f13a24ab7fc5fe"
		logic_hash = "52cba9545f662da18ca6e07340d7a9be637b89e7ed702dd58cac545c702a00e3"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
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
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L35-L56"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "4935f0c50057e28efa7376c734a4c66018f8d20157b6584399146b6c79a6de15"
		logic_hash = "d3048aba80c1c39f1673931cd2d7c5ed83045603b0ad204073fd788d0103a6c8"
		score = 65
		quality = 80
		tags = "FILE, MEMORY"
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
rule VOLEXITY_Webshell_Java_Behinder_Shellservice : FILE MEMORY {
    meta:
		description = "Looks for artifacts generated (generally seen in .class files) related to the Behinder webshell."
		author = "threatintel@volexity.com"
		id = "21c1e3e9-d048-5c60-9c21-8e54b27f359a"
		date = "2022-03-18"
		modified = "2024-07-30"
		reference = "https://github.com/MountCloud/BehinderClientSource/blob/master/src/main/java/net/rebeyond/behinder/core/ShellService.java"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L1-L29"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "9a9882f9082a506ed0fc4ddaedd50570c5762deadcaf789ac81ecdbb8cf6eff2"
		logic_hash = "373a8d4ef81e9bbbf1f24ebf0389e7da4b73f88786cc8e1d286ccc9f4c36debc"
		score = 75
		quality = 30
		tags = "FILE, MEMORY"
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
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L90-L120"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "8297c99391aae918f154077c61ea94a99c7a339166e7981d9912b7fdc2e0d4f0"
		logic_hash = "791a664a6b4b98051cbfacb451099de085cbab74d73771709377ab68a5a23d2b"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
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
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L121-L158"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "7474a6008b99e45686678f216af7d6357bb70a054c6d9b05e1817c8d80d536b4"
		logic_hash = "f5b5f35ee783ff1163072591c6d48a85894729156935650a0fd166ae22a2ea00"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
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
rule VOLEXITY_Apt_Malware_Js_Sharpext : SHARPPINE FILE MEMORY {
    meta:
		description = "A malicious Chrome browser extension used by the SharpPine threat actor to steal Gmail data from a victim."
		author = "threatintel@volexity.com"
		id = "61b5176a-ff73-5fce-bc70-c9e09bb5afed"
		date = "2021-09-14"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2022/2022-07-28 SharpTongue SharpTongue Deploys Clever Mail-Stealing Browser Extension SHARPEXT/yara.yar#L1-L52"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "1c9664513fe226beb53268b58b11dacc35b80a12c50c22b76382304badf4eb00"
		hash = "6025c66c2eaae30c0349731beb8a95f8a5ba1180c5481e9a49d474f4e1bb76a4"
		hash = "6594b75939bcdab4253172f0fa9066c8aee2fa4911bd5a03421aeb7edcd9c90c"
		logic_hash = "0ed58c8646582ee36aeac650fac02d1e4962d45c0f6a24783c021d9267bed192"
		score = 75
		quality = 80
		tags = "SHARPPINE, FILE, MEMORY"
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
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L1-L21"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
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
		source_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L61-L84"
		license_url = "https://github.com/volexity/threat-intel/blob/a7eaa9d97a5d0c193f4a3ac99a6239e6ccc211de/LICENSE.txt"
		hash = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
		logic_hash = "e09f2a23674fd73296dd4d1fabf1a2c812bfe69ff02abc96a4be35af6a18e512"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
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
rule HARFANGLAB_Nhas_Reverse_Shell_Elf_Inmem_Large {
    meta:
		description = "Matches packed NHAS reverse_ssh ELF samples in-memory during execution"
		author = "HarfangLab"
		id = "cd6f7b81-b8df-5e2b-9da6-981d1f62c131"
		date = "2024-09-24"
		modified = "2026-05-18"
		reference = "TRR250201"
		source_url = "https://github.com/HarfangLab/iocs/blob/3e2b674bf2f591ac46301420671ba553de094dea/hl_public_reports_master.yar#L430-L447"
		license_url = "N/A"
		hash = "9f97997581f513166aae47b3664ca23c4f4ea90c24916874ff82891e2cd6e01e"
		logic_hash = "54ba4fc366fb6e4a252d51528ede3ec418b369881ad98e9119d1a9650b6a1bab"
		score = 75
		quality = 80
		tags = ""
		context = "memory"

	strings:
		$s1 = "/NHAS/reverse_ssh/cmd/client" ascii
		$s2 = "/handlers.runCommandWithPty" ascii
		$s3 = "/connection.RegisterChannelCallbacks" ascii
		$s4 = "/internal.RemoteForwardRequest" ascii
		$s7 = "main.Fork" ascii fullword

	condition:
		( all of them )
}
