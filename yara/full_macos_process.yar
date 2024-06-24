        rule ELASTIC_Macos_Trojan_Electrorat_B4Dbfd1D : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Electrorat (MacOS.Trojan.Electrorat)"
        		author = "Elastic Security"
        		id = "b4dbfd1d-4968-4121-a4c2-5935b7f76fc1"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Electrorat.yar#L1-L22"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "b1028b38fcce0d54f2013c89a9c0605ccb316c36c27faf3a35adf435837025a4"
        		logic_hash = "a36143a8c93cb187dba0a88a15550219c19f1483502f782dfefc1e53829cfbf1"
        		score = 75
        		quality = 71
        		tags = "FILE, MEMORY"
        		fingerprint = "fa65fc0a8f5b1f63957c586e6ca8e8fbdb811970f25a378a4ff6edf5e5c44da7"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = "_TtC9Keylogger9Keylogger" ascii fullword
        		$a2 = "_TtC9Keylogger17CallBackFunctions" ascii fullword
        		$a3 = "\\DELETE-FORWARD" ascii fullword
        		$a4 = "\\CAPSLOCK" ascii fullword
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Fplayer_1C1Fae37 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Fplayer (MacOS.Trojan.Fplayer)"
        		author = "Elastic Security"
        		id = "1c1fae37-8d19-4129-a715-b78163f93fd2"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Fplayer.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "f57e651088dee2236328d09705cef5e98461e97d1eb2150c372d00ca7c685725"
        		logic_hash = "0d65717bdbac694ffb2535a1ff584f7ec2aa7b553a08d29113c6e2bd7b2ff1aa"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "abeb3cd51c0ff2e3173739c423778defb9a77bc49b30ea8442e6ec93a2d2d8d2"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 56 41 55 41 54 53 48 83 EC 48 4D 89 C4 48 89 C8 48 89 D1 49 89 F6 49 89 FD 49 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Rustbucket_E64F7A92 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Rustbucket (MacOS.Trojan.RustBucket)"
        		author = "Elastic Security"
        		id = "e64f7a92-e530-4d0b-8ecb-fe5756ad648c"
        		date = "2023-06-26"
        		modified = "2023-06-29"
        		reference = "https://www.elastic.co/security-labs/DPRK-strikes-using-a-new-variant-of-rustbucket"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_RustBucket.yar#L1-L22"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
        		logic_hash = "bd6005d72faba6aaeebdcbd8c771995cbfc667faf01eb93825afe985954a47fc"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "f9907f46c345a874b683809f155691723e3a6df7c48f6f4e6eb627fb3dd7904d"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$user_agent = "User-AgentMozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)"
        		$install_log = "/var/log/install.log"
        		$timestamp = "%Y-%m-%d %H:%M:%S"
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Cryptominer_Xmrig_241780A1 : FILE MEMORY {
            meta:
        		description = "Detects Macos Cryptominer Xmrig (MacOS.Cryptominer.Xmrig)"
        		author = "Elastic Security"
        		id = "241780a1-ad50-4ded-b85a-26339ae5a632"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Cryptominer_Xmrig.yar#L1-L22"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "2e94fa6ac4045292bf04070a372a03df804fa96c3b0cb4ac637eeeb67531a32f"
        		logic_hash = "9e091f6881a96abdc6592db385eb9026806befdda6bda4489470b4e16e1d4d87"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "be9c56f18e0f0bdc8c46544039b9cb0bbba595c1912d089b2bcc7a7768ac04a8"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = "mining.set_target" ascii fullword
        		$a2 = "XMRIG_HOSTNAME" ascii fullword
        		$a3 = "Usage: xmrig [OPTIONS]" ascii fullword
        		$a4 = "XMRIG_VERSION" ascii fullword
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Aobokeylogger_Bd960F34 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Aobokeylogger (MacOS.Trojan.Aobokeylogger)"
        		author = "Elastic Security"
        		id = "bd960f34-1932-41be-ac0a-f45ada22c560"
        		date = "2021-10-18"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Aobokeylogger.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "2b50146c20621741642d039f1e3218ff68e5dbfde8bb9edaa0a560ca890f0970"
        		logic_hash = "f89fbf1d6bf041de0ce32f7920818c34ce0eeb6779bb7fac6f223bbea1c6f6fa"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "ae26a03d1973669cbeaabade8f3fd09ef2842b9617fa38e7b66dc4726b992a81"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 20 74 68 61 6E 20 32 30 30 20 6B 65 79 73 74 72 6F 6B 65 73 20 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Kandykorn_A7Bb6944 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Kandykorn (MacOS.Trojan.KandyKorn)"
        		author = "Elastic Security"
        		id = "a7bb6944-90fa-40ba-840c-f044f12dcb39"
        		date = "2023-10-23"
        		modified = "2023-10-23"
        		reference = "https://www.elastic.co/security-labs/elastic-catches-dprk-passing-out-kandykorn"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_KandyKorn.yar#L1-L29"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "51dd4efcf714e64b4ad472ea556bf1a017f40a193a647b9e28bf356979651077"
        		logic_hash = "65decd519dee947894dd684c52d91202ebe5587acfecc0b8b56cd73f2981e387"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "f2b2ebc056c79448b077dce140b2a73d6791b61ddc8bf21d4c565c95f5de49e7"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$str_1 = "resp_file_dir"
        		$str_2 = "resp_cfg_set"
        		$str_3 = "resp_proc_kill"
        		$str_4 = "/com.apple.safari.ck" ascii fullword
        		$str_5 = "/chkupdate.XXX" ascii fullword
        		$seq_file_dir = { 83 7D ?? ?? 0F 8E ?? ?? ?? ?? 48 63 45 ?? 48 83 C0 ?? 48 8B 4D ?? 0F B7 49 ?? 48 01 C8 48 83 C0 01 48 3D 00 00 0A 00 0F 86 ?? ?? ?? ?? }
        		$seq_cmd_send = { 8B 45 ?? 83 F8 ?? 0F 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 78 ?? 48 8B 70 ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
        		$seq_cfg_get = { 8B 45 ?? 83 F8 ?? 0F 8C ?? ?? ?? ?? 48 8B 45 ?? 48 8B 38 48 8B 70 ?? 8B 55 ?? E8 ?? ?? ?? ?? 89 45 ?? E9 ?? ?? ?? ?? }
        		$seq_proc_list = { 48 83 F8 ?? 0F 85 ?? ?? ?? ?? 8B 4D ?? 48 8B 85 ?? ?? ?? ?? 89 48 ?? 8B 4D ?? 48 8B 85 ?? ?? ?? ?? 89 48 ?? 8B 4D ?? 48 8B 85 ?? ?? ?? ?? }
        		$rc4_key = { D9 F9 36 CE 62 8C 3E 5D 9B 36 95 69 4D 1C DE 79 E4 70 E9 38 06 4D 98 FB F4 EF 98 0A 55 58 D1 C9 0C 7E 65 0C 23 62 A2 1B 91 4A BD 17 3A BA 5C 0E 58 37 C4 7B 89 F7 4C 5B 23 A7 29 4C C1 CF D1 1B }
        
        	condition:
        		4 of ($str*) or 3 of ($seq*) or $rc4_key
        }
        rule ELASTIC_Macos_Virus_Maxofferdeal_53Df500F : FILE MEMORY {
            meta:
        		description = "Detects Macos Virus Maxofferdeal (MacOS.Virus.Maxofferdeal)"
        		author = "Elastic Security"
        		id = "53df500f-3add-4d3d-aec3-35b7b5aa5b35"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Virus_Maxofferdeal.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
        		logic_hash = "ed63c14e31c200f906b525c7ef1cd671511a89c8833cfa1a605fc9870fe91043"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "2f41de7b8e55ef8db39bf84c0f01f8d34d67b087769b84381f2ccc3778e13b08"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Virus_Maxofferdeal_F4681Eba : FILE MEMORY {
            meta:
        		description = "Detects Macos Virus Maxofferdeal (MacOS.Virus.Maxofferdeal)"
        		author = "Elastic Security"
        		id = "f4681eba-20f5-4e92-9f99-00cd57412c45"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Virus_Maxofferdeal.yar#L21-L39"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "ecd62ef880da057726ca55c6826ce4e1584ec6fc3afaabed7f66154fc39ffef8"
        		logic_hash = "cf478ec5313b40d74d110e4d6e97da5f671d5af331adc3ab059a69616e78c76c"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "b6663c326e9504510b804bd9ff0e8ace5d98826af2bb2fa2429b37171b7f399d"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { BA A4 C8 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 AC AD AE A9 BD A4 BC 97 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Virus_Maxofferdeal_4091E373 : FILE MEMORY {
            meta:
        		description = "Detects Macos Virus Maxofferdeal (MacOS.Virus.Maxofferdeal)"
        		author = "Elastic Security"
        		id = "4091e373-c3a9-41c8-a1d8-3a77585ff850"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Virus_Maxofferdeal.yar#L41-L59"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "c38c4bdd3c1fa16fd32db06d44d0db1b25bb099462f8d2936dbdd42af325b37c"
        		logic_hash = "ce82f6d3a2e4b7ffe7010629bf91a9144a94e50513682a6c0622603d28248d51"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "3d8e7db6c39286d9626c6be8bfb5da177a6a4f8ffcec83975a644aaac164a8c7"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { B8 F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 8B 8E 8A BD A6 AC A4 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Virus_Maxofferdeal_20A0091E : FILE MEMORY {
            meta:
        		description = "Detects Macos Virus Maxofferdeal (MacOS.Virus.Maxofferdeal)"
        		author = "Elastic Security"
        		id = "20a0091e-a3ef-4a13-ba92-700f3583e06d"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Virus_Maxofferdeal.yar#L61-L79"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "b00a61c908cd06dbc26bee059ba290e7ce2ad6b66c453ea272c7287ffa29c5ab"
        		logic_hash = "bb90b7e1637fd86e91763b4801a0b3bb8a1b956f328d07e96cf1b26e42b1931b"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "1629b34b424816040066122592e56e317b204f3d5de2f5e7f68114c7a48d99cb"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 A0 BC BC B8 F2 E7 E7 BF }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Getshell_F339D74C : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Getshell (MacOS.Trojan.Getshell)"
        		author = "Elastic Security"
        		id = "f339d74c-36f1-46e5-bf7d-22f49a0948a5"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Getshell.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "b2199c15500728a522c04320aee000938f7eb69d751a55d7e51a2806d8cd0fe7"
        		logic_hash = "77a409f1a0ab5f87a77a6b2ffa2d4ff7bd6d86c0f685c524e2083585bb3fb764"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "fad5ca4f345c2c01a3d222f59bac8d5dacf818d4e018c8d411d86266a481a1a1"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 00 00 FF E0 E8 00 00 00 00 58 8B 80 4B 22 00 00 FF E0 55 89 E5 53 83 EC 04 E8 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Backdoor_Useragent_1A02Fc3A : FILE MEMORY {
            meta:
        		description = "Detects Macos Backdoor Useragent (MacOS.Backdoor.Useragent)"
        		author = "Elastic Security"
        		id = "1a02fc3a-a394-457b-8af5-99f7f22b0a3b"
        		date = "2021-11-11"
        		modified = "2022-07-22"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Backdoor_Useragent.yar#L1-L23"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
        		logic_hash = "90debdfc24ef100952302808a2e418bca2a46be3e505add9a0ccf4c49aff5102"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "22afa14a3dc6f8053b93bf3e971d57808a9cc19e676f9ed358ba5f1db9292ba4"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$s1 = "/Library/LaunchAgents/com.UserAgent.va.plist"
        		$s2 = "this is not root"
        		$s3 = "rm -Rf "
        		$s4 = "/start.sh"
        		$s5 = ".killchecker_"
        
        	condition:
        		4 of them
        }
        rule ELASTIC_Macos_Backdoor_Applejeus_31872Ae2 : FILE MEMORY {
            meta:
        		description = "Detects Macos Backdoor Applejeus (MacOS.Backdoor.Applejeus)"
        		author = "Elastic Security"
        		id = "31872ae2-f6df-4079-89c2-866cb2e62ec8"
        		date = "2021-10-18"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Backdoor_Applejeus.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
        		logic_hash = "1d6f06668a7d048a93e53b294c5ab8ffe4cd610f3bef3fd80f14425ef8a85a29"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "24b78b736f691e6b84ba88b0bb47aaba84aad0c0e45cf70f2fa8c455291517df"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { FF CE 74 12 89 F0 31 C9 80 34 0F 63 48 FF C1 48 39 C8 75 F4 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Genieo_5E0F8980 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Genieo (MacOS.Trojan.Genieo)"
        		author = "Elastic Security"
        		id = "5e0f8980-1789-4763-9e41-a521bdb3ff34"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Genieo.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "6c698bac178892dfe03624905256a7d9abe468121163d7507cade48cf2131170"
        		logic_hash = "76b725f6ae5755bb00d384ef2ae1511789487257d8bb7cb61b893226f03a803e"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "f0b5198ce85d19889052a7e33fb7cf32a7725c4fdb384ffa7d60d209a7157092"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 00 CD 01 1E 68 57 58 D7 56 7C 62 C9 27 3C C6 15 A9 3D 01 02 2F E1 69 B5 4A 11 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Genieo_37878473 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Genieo (MacOS.Trojan.Genieo)"
        		author = "Elastic Security"
        		id = "37878473-b6f8-4cbe-ba70-31ecddf41c82"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Genieo.yar#L21-L39"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "0fadd926f8d763f7f15e64f857e77f44a492dcf5dc82ae965d3ddf80cd9c7a0d"
        		logic_hash = "bb04ae4e0a98e0dbd0c0708d5e767306e38edf76de2671523f4bd43cbcbfefc2"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "e9760bda6da453f75e543c919c260a4560989f62f3332f28296283d4c01b62a2"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 65 72 6E 61 6C 44 6F 77 6E 4C 6F 61 64 55 72 6C 46 6F 72 42 72 61 6E 64 3A 5D }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Genieo_0D003634 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Genieo (MacOS.Trojan.Genieo)"
        		author = "Elastic Security"
        		id = "0d003634-8b17-4e26-b4a2-4bfce2e64dde"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Genieo.yar#L41-L59"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "bcd391b58338efec4769e876bd510d0c4b156a7830bab56c3b56585974435d70"
        		logic_hash = "0412f88408fb14d1126ef091d0a5cc0ee2b2e39aeb241bef55208b59830ca993"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "6f38b7fc403184482449957aff51d54ac9ea431190c6f42c7a5420efbfdb8f7d"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 75 69 6C 64 2F 41 6E 61 62 65 6C 50 61 63 6B 61 67 65 2F 62 75 69 6C 64 2F 73 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Genieo_9E178C0B : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Genieo (MacOS.Trojan.Genieo)"
        		author = "Elastic Security"
        		id = "9e178c0b-02ca-499b-93d1-2b6951d41435"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Genieo.yar#L61-L79"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "b7760e73195c3ea8566f3ff0427d85d6f35c6eec7ee9184f3aceab06da8845d8"
        		logic_hash = "212f96ca964aceeb80c6d3282d488cfbb74aeffb9c0c9dd840a3a28f9bbdcbea"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "b00bffbdac79c5022648bf8ca5a238db7e71f3865a309f07d068ee80ba283b82"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 4D 49 70 67 41 59 4B 6B 42 5A 59 53 65 4D 6B 61 70 41 42 48 4D 5A 43 63 44 44 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Backdoor_Kagent_64Ca1865 : FILE MEMORY {
            meta:
        		description = "Detects Macos Backdoor Kagent (MacOS.Backdoor.Kagent)"
        		author = "Elastic Security"
        		id = "64ca1865-0a99-49dc-b138-02b17ed47f60"
        		date = "2021-11-11"
        		modified = "2022-07-22"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Backdoor_Kagent.yar#L1-L25"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
        		logic_hash = "dea0a1bbe8c3065b395de50b5ffc2fbdf479ed35ce284fa33298d6ed55e960c6"
        		score = 75
        		quality = 50
        		tags = "FILE, MEMORY"
        		fingerprint = "b8086b08a019a733bee38cebdc4e25cdae9d3c238cfe7b341d8f0cd4db204d27"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$s1 = "save saveCaptureInfo"
        		$s2 = "savephoto success screenCaptureInfo"
        		$s3 = "no auto bbbbbaaend:%d path %s"
        		$s4 = "../screencapture/screen_capture_thread.cpp"
        		$s5 = "%s:%d, m_autoScreenCaptureQueue: %x"
        		$s6 = "auto bbbbbaaend:%d path %s"
        		$s7 = "auto aaaaaaaastartTime:%d path %s"
        
        	condition:
        		4 of them
        }
        rule ELASTIC_Macos_Virus_Vsearch_0Dd3Ec6F : FILE MEMORY {
            meta:
        		description = "Detects Macos Virus Vsearch (MacOS.Virus.Vsearch)"
        		author = "Elastic Security"
        		id = "0dd3ec6f-815f-40e1-bd53-495e0eae8196"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Virus_Vsearch.yar#L1-L18"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "17a467b000117ea6c39fbd40b502ac9c7d59a97408c2cdfb09c65b2bb09924e5"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "8adbd06894e81dc09e46d8257d4e5fcd99e714f54ffb36d5a8d6268ea25d0bd6"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 2F 00 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6D 00 2F 4D 61 63 69 6E 74 6F 73 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Virus_Vsearch_2A0419F8 : FILE MEMORY {
            meta:
        		description = "Detects Macos Virus Vsearch (MacOS.Virus.Vsearch)"
        		author = "Elastic Security"
        		id = "2a0419f8-95b2-4f87-a37a-ee0b65e344e9"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Virus_Vsearch.yar#L20-L37"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "fa9b811465e435bff5bc0f149ff65f57932c94f548a5ece4ec54ba775cdbb55a"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "2da9f0fc05bc8e23feb33b27142f46fb437af77766e39889a02ea843d52d17eb"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 6F 72 6D 61 6C 2F 69 33 38 36 2F 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6F 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Adload_4995469F : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Adload (MacOS.Trojan.Adload)"
        		author = "Elastic Security"
        		id = "4995469f-9810-4c1f-b9bc-97e951fe9256"
        		date = "2021-10-04"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Adload.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "6464ca7b36197cccf0dac00f21c43f0cb09f900006b1934e2b3667b367114de5"
        		logic_hash = "cceb804a11b93b0e3f491016c47a823d9e6a31294c3ed05d4404601323b30993"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "9b7e7c76177cc8ca727df5039a5748282f5914f2625ec1f54d67d444f92f0ee5"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 49 8B 77 08 49 8B 4F 20 48 BF 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E7 48 C1 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Adload_9B9F86C7 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Adload (MacOS.Trojan.Adload)"
        		author = "Elastic Security"
        		id = "9b9f86c7-e74c-4fc2-bb64-f87473a4b820"
        		date = "2021-10-04"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Adload.yar#L21-L39"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "952e6004ce164ba607ac7fddc1df3d0d6cac07d271d90be02d790c52e49cb73c"
        		logic_hash = "82297db23e036f22c90eee7b2654e84df847eb1c2b1ea4dcf358c48a14819709"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "7e70d5574907261e73d746a4ad0b7bce319a9bb3b39a7f1df326284960a7fa38"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 44 65 6C 65 67 61 74 65 43 35 73 68 6F 77 6E 53 62 76 70 57 76 64 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Adload_F6B18A0A : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Adload (MacOS.Trojan.Adload)"
        		author = "Elastic Security"
        		id = "f6b18a0a-7593-430f-904b-8d416861d165"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Adload.yar#L41-L59"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "06f38bb811e6a6c38b5e2db708d4063f4aea27fcd193d57c60594f25a86488c8"
        		logic_hash = "20d43fbf0b8155940e2e181f376a7b1979ce248d88dc08409aaa1a916777231c"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "f33275481b0bf4f4e57c7ad757f1e22d35742fc3d0ffa3983321f03170b5100e"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 10 49 8B 4E 20 48 BE 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E6 49 39 DC 0F 84 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Eggshell_Ddacf7B9 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Eggshell (MacOS.Trojan.Eggshell)"
        		author = "Elastic Security"
        		id = "ddacf7b9-8479-47ef-9df2-17060578a8e5"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Eggshell.yar#L1-L23"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "6d93a714dd008746569c0fbd00fadccbd5f15eef06b200a4e831df0dc8f3d05b"
        		logic_hash = "f986f7d1e3a68e27f82048017c6d6381a0354ffad2cd10f3eee69bbbfa940abd"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "2e6284c8e44809d5f88781dcf7779d1e24ce3aedd5e8db8598e49c01da63fe62"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = "ScreenshotThread" ascii fullword
        		$a2 = "KeylogThread" ascii fullword
        		$a3 = "GetClipboardThread" ascii fullword
        		$a4 = "_uploadProgress" ascii fullword
        		$a5 = "killTask:" ascii fullword
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Cryptominer_Generic_D3F68E29 : FILE MEMORY {
            meta:
        		description = "Detects Macos Cryptominer Generic (MacOS.Cryptominer.Generic)"
        		author = "Elastic Security"
        		id = "d3f68e29-830d-4d40-a285-ac29aed732fa"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Cryptominer_Generic.yar#L1-L21"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "d9c78c822dfd29a1d9b1909bf95cab2a9550903e8f5f178edeb7a5a80129fbdb"
        		logic_hash = "cc336e536e0f8dda47f9551dfabfc50c2094fffe4a69cdcec23824dd063dede0"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "733dadf5a09f4972629f331682fca167ebf9a438004cb686d032f69e32971bd4"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = "command line argument. See 'ethminer -H misc' for details." ascii fullword
        		$a2 = "Ethminer - GPU ethash miner" ascii fullword
        		$a3 = "StratumClient"
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Cryptominer_Generic_365Ecbb9 : FILE MEMORY {
            meta:
        		description = "Detects Macos Cryptominer Generic (MacOS.Cryptominer.Generic)"
        		author = "Elastic Security"
        		id = "365ecbb9-586e-4962-a5a8-05e871f54eff"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Cryptominer_Generic.yar#L23-L41"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
        		logic_hash = "66f16c8694c5cfde1b5e4eea03c530fa32a15022fa35acdbb676bb696e7deae2"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "5ff82ab60f8d028c9e4d3dd95609f92cfec5f465c721d96947b490691d325484"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 55 6E 6B 6E 6F 77 6E 20 6E 65 74 77 6F 72 6B 20 73 70 65 63 69 66 69 65 64 20 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Cryptominer_Generic_4E7D4488 : FILE MEMORY {
            meta:
        		description = "Detects Macos Cryptominer Generic (MacOS.Cryptominer.Generic)"
        		author = "Elastic Security"
        		id = "4e7d4488-2e0c-4c74-84f9-00da103e162a"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Cryptominer_Generic.yar#L43-L61"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
        		logic_hash = "708b21b687c8b853a9b5f8a50d31119e4f0a02a5b63f81ba1cac8c06acd19214"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "4e7f22e8084734aeded9b1202c30e6a170a6a38f2e486098b4027e239ffed2f6"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 69 73 20 66 69 65 6C 64 20 74 6F 20 73 68 6F 77 20 6E 75 6D 62 65 72 20 6F 66 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Generic_A829D361 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Generic (MacOS.Trojan.Generic)"
        		author = "Elastic Security"
        		id = "a829d361-ac57-4615-b8e9-16089c44d7af"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Generic.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "5b2a1cd801ae68a890b40dbd1601cdfeb5085574637ae8658417d0975be8acb5"
        		logic_hash = "70a954e8b44b1ce46f5ce0ebcf43b46e1292f0b8cdb46aa67f980d3c9b0a6f61"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "5dba43dbc5f4d5ee295e65d66dd4e7adbdb7953232faf630b602e6d093f69584"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { E7 81 6A 12 EA A8 56 6C 86 94 ED F6 E8 D7 35 E1 EC 65 47 BA 8E 46 2C A6 14 5F }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Virus_Pirrit_271B8Ed0 : FILE MEMORY {
            meta:
        		description = "Detects Macos Virus Pirrit (MacOS.Virus.Pirrit)"
        		author = "Elastic Security"
        		id = "271b8ed0-937a-4be6-aecb-62535b5aeda7"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Virus_Pirrit.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "7feda05d41b09c06a08c167c7f4dde597ac775c54bf0d74a82aa533644035177"
        		logic_hash = "cb77f6df1403afbc7f45d30551559b6de7eb1c3434778b46d31754da0a1b1f10"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "12b09b2e3a43905db2cfe96d0fd0e735cfc7784ee7b03586c5d437d7c6a1b422"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 4A 6A 00 00 32 80 35 44 6A 00 00 75 80 35 3E 6A 00 00 1F 80 35 38 6A 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Sugarloader_E7E1D99C : FILE MEMORY {
            meta:
        		description = "Identifies unpacked SugarLoader sample"
        		author = "Elastic Security"
        		id = "e7e1d99c-355e-4672-9176-d9eb5d2729c4"
        		date = "2023-10-24"
        		modified = "2023-10-24"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_SugarLoader.yar#L1-L23"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "3ea2ead8f3cec030906dcbffe3efd5c5d77d5d375d4a54cca03bfe8a6cb59940"
        		logic_hash = "0689b704add81e8e7968d9dba5f60d45c8791209330f4ee97e218f8eeb22c88f"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "cfffdab1e603518df48719266f0a2e91763e5ae7c033d4bf7a4c37232aa8eb04"
        		threat_name = "MacOS.Trojan.SugarLoader"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$seq_process_key = { 44 0F B6 0C 0F 89 C8 99 F7 BF ?? ?? ?? ?? 0F B6 84 17 ?? ?? ?? ?? 4C 21 C6 4C 01 CE 48 01 C6 }
        		$seq_handshake = { E8 ?? ?? ?? ?? 4C 8D 75 ?? 48 89 DF 4C 89 F6 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 8B 06 C1 C0 ?? 44 21 F8 4C 8D 75 ?? 41 89 06 48 89 DF 4C 89 F6 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        		$seq_config = { 48 89 F7 48 C1 E7 05 48 29 F7 48 0F BE D1 48 01 FA 89 D6 8A 08 48 FF C0 84 C9 75 ?? EB ?? }
        		$seq_recieve_msg = { 45 85 FF 74 ?? 45 39 EF BA ?? ?? ?? ?? 41 0F 42 D7 41 8B 3C 24 48 89 DE 31 C9 E8 ?? ?? ?? ?? 41 29 C7 48 01 C3 48 85 C0 7F ?? B8 ?? ?? ?? ?? EB ?? }
        
        	condition:
        		3 of ($seq*)
        }
        rule ELASTIC_Macos_Trojan_Thiefquest_9130C0F3 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
        		author = "Elastic Security"
        		id = "9130c0f3-5926-4153-87d8-85a591eed929"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Thiefquest.yar#L1-L22"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "bed3561210e44c290cd410adadcdc58462816a03c15d20b5be45d227cd7dca6b"
        		logic_hash = "20e9ea15a437a17c4ef68f2472186f6d1ab3118d5b392f84fcb2bd376ec3863a"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "38916235c68a329eea6d41dbfba466367ecc9aad2b8ae324da682a9970ec4930"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = "heck_if_targeted" ascii fullword
        		$a2 = "check_command" ascii fullword
        		$a3 = "askroot" ascii fullword
        		$a4 = "iv_rescue_data" ascii fullword
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Thiefquest_Fc2E1271 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
        		author = "Elastic Security"
        		id = "fc2e1271-3c96-4c93-9e3d-212782928e6e"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Thiefquest.yar#L24-L42"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        		logic_hash = "a20c76e53874fc0fec5fd2660c63c6f1e7c1b2055cbd2a9efdfd114cd6bdda5c"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "195e8f65e4ea722f0e1ba171f2ad4ded97d4bc97da38ef8ac8e54b8719e4c5ae"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 30 30 30 42 67 7B 30 30 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Thiefquest_86F9Ef0C : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
        		author = "Elastic Security"
        		id = "86f9ef0c-832e-4e4a-bd39-c80c1d064dbe"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Thiefquest.yar#L44-L62"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "59fb018e338908eb69be72ab11837baebf8d96cdb289757f1f4977228e7640a0"
        		logic_hash = "426d533d39e594123f742b15d0a93ded986b9b308685f7b2cfaf5de0b32cdbff"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "e8849628ee5449c461f1170c07b6d2ebf4f75d48136f26b52bee9bcf4e164d5b"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 6C 65 31 6A 6F 57 4E 33 30 30 30 30 30 33 33 00 30 72 7A 41 43 47 33 57 72 7C }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Thiefquest_40F9C1C3 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
        		author = "Elastic Security"
        		id = "40f9c1c3-29f8-4699-8f66-9b7ddb08f92d"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Thiefquest.yar#L64-L82"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "e402063ca317867de71e8e3189de67988e2be28d5d773bbaf75618202e80f9f6"
        		logic_hash = "546edc2d6d715eac47e7a8d3ceb91cf314fa6dbee04f0475a5c4a84ba53fd722"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "27ec200781541d5b1abc96ffbb54c428b773bffa0744551bbacd605c745b6657"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 7C 49 56 7C 6A 30 30 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Thiefquest_0F9Fe37C : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
        		author = "Elastic Security"
        		id = "0f9fe37c-77df-4d3d-be8a-c62ea0f6863c"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Thiefquest.yar#L84-L102"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        		logic_hash = "84f9e8938d7e2b0210003fc8334b8fa781a40afffeda8d2341970b84ed5d3b5a"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "2e809d95981f0ff813947f3be22ab3d3c000a0d348131d5d6c8522447818196d"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 71 6B 6E 6C 55 30 55 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Thiefquest_1F4Bac78 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
        		author = "Elastic Security"
        		id = "1f4bac78-ef2b-49cd-8852-e84d792f6e57"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Thiefquest.yar#L104-L122"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        		logic_hash = "96db33e135138846f978026867bb2536226539997d060f41e7081f7f29b66c85"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "e7d1e2009ff9b33d2d237068e2af41a8aa9bd44a446a2840c34955594f060120"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 32 33 4F 65 49 66 31 68 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Hacktool_Jokerspy_58A6B26D : FILE MEMORY {
            meta:
        		description = "Detects Macos Hacktool Jokerspy (Macos.Hacktool.JokerSpy)"
        		author = "Elastic Security"
        		id = "58a6b26d-13dd-485a-bac3-77a1053c3a02"
        		date = "2023-06-19"
        		modified = "2023-06-19"
        		reference = "https://www.elastic.co/security-labs/inital-research-of-jokerspy"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/Macos_Hacktool_JokerSpy.yar#L1-L25"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
        		logic_hash = "e9e1333c7172d5a0f06093a902edefd7f128963dbaadf77e829f032ccb04ce56"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "71423d5c4c917917281b7e0f644142a0570df7a5a7ea568506753cb6eabef1c0"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$str1 = "ScreenRecording: NO" fullword
        		$str2 = "Accessibility: NO" fullword
        		$str3 = "Accessibility: YES" fullword
        		$str4 = "eck13XProtectCheck"
        		$str5 = "Accessibility: NO" fullword
        		$str6 = "kMDItemDisplayName = *TCC.db" fullword
        
        	condition:
        		5 of them
        }
        rule ELASTIC_Macos_Creddump_Keychainaccess_535C1511 : FILE MEMORY {
            meta:
        		description = "Detects Macos Creddump Keychainaccess (Macos.Creddump.KeychainAccess)"
        		author = "Elastic Security"
        		id = "535c1511-5b45-4845-85c1-ec53f9787b96"
        		date = "2023-04-11"
        		modified = "2024-01-30"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Creddump_KeychainAccess.yar#L1-L25"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "5234dcab6c9ca994c3d40243d882bd50e51fd77bba107e37ef494a04f6bf6112"
        		score = 75
        		quality = 49
        		tags = "FILE, MEMORY"
        		fingerprint = "713fd9a4ed51875cb2ce546f146e643fc7fccd2b2e280f0f2707de4eb4b70ee1"
        		severity = 100
        		arch_context = "x86, arm64"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$strings1 = "uploadkeychain" ascii wide nocase
        		$strings2 = "decryptkeychain" ascii wide nocase
        		$strings3 = "dump-generic-password" ascii wide nocase
        		$strings4 = "keychain_extract" ascii wide nocase
        		$strings5 = "chainbreaker" ascii wide nocase
        		$strings6 = "SecKeychainItemCopyContent" ascii wide nocase
        		$strings7 = "SecKeychainItemCopyAccess" ascii wide nocase
        		$strings8 = "Failed to get password" ascii wide nocase
        
        	condition:
        		all of ($strings1,$strings2) or any of ($strings3,$strings4,$strings5) or all of ($strings6,$strings7,$strings8)
        }
        rule ELASTIC_Macos_Hacktool_Swiftbelt_Bc62Ede6 : FILE MEMORY {
            meta:
        		description = "Detects Macos Hacktool Swiftbelt (MacOS.Hacktool.Swiftbelt)"
        		author = "Elastic Security"
        		id = "bc62ede6-e6f1-4c9e-bff2-ef55a5d12ba1"
        		date = "2021-10-12"
        		modified = "2021-10-25"
        		reference = "https://www.elastic.co/security-labs/inital-research-of-jokerspy"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Hacktool_Swiftbelt.yar#L1-L44"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "452c832a17436f61ad5f32ee1c97db05575160105ed1dcd0d3c6db9fb5a9aea1"
        		logic_hash = "51481baa6ddb09cf8463d989637319cb26b23fef625cc1a44c96d438c77362ca"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "98d14dba562ad68c8ecc00780ab7ee2ecbe912cd00603fff0eb887df1cd12fdb"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$dbg1 = "SwiftBelt/Sources/SwiftBelt"
        		$dbg2 = "[-] Firefox places.sqlite database not found for user"
        		$dbg3 = "[-] No security products found"
        		$dbg4 = "SSH/AWS/gcloud Credentials Search:"
        		$dbg5 = "[-] Could not open the Slack Cookies database"
        		$sec1 = "[+] Malwarebytes A/V found on this host"
        		$sec2 = "[+] Cisco AMP for endpoints found"
        		$sec3 = "[+] SentinelOne agent running"
        		$sec4 = "[+] Crowdstrike Falcon agent found"
        		$sec5 = "[+] FireEye HX agent installed"
        		$sec6 = "[+] Little snitch firewall found"
        		$sec7 = "[+] ESET A/V installed"
        		$sec8 = "[+] Carbon Black OSX Sensor installed"
        		$sec9 = "/Library/Little Snitch"
        		$sec10 = "/Library/FireEye/xagt"
        		$sec11 = "/Library/CS/falcond"
        		$sec12 = "/Library/Logs/PaloAltoNetworks/GlobalProtect"
        		$sec13 = "/Library/Application Support/Malwarebytes"
        		$sec14 = "/usr/local/bin/osqueryi"
        		$sec15 = "/Library/Sophos Anti-Virus"
        		$sec16 = "/Library/Objective-See/Lulu"
        		$sec17 = "com.eset.remoteadministrator.agent"
        		$sec18 = "/Applications/CarbonBlack/CbOsxSensorService"
        		$sec19 = "/Applications/BlockBlock Helper.app"
        		$sec20 = "/Applications/KextViewr.app"
        
        	condition:
        		6 of them
        }
        rule ELASTIC_Macos_Hacktool_Bifrost_39Bcbdf8 : FILE MEMORY {
            meta:
        		description = "Detects Macos Hacktool Bifrost (MacOS.Hacktool.Bifrost)"
        		author = "Elastic Security"
        		id = "39bcbdf8-86dc-480e-8822-dc9832bb9b55"
        		date = "2021-10-12"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Hacktool_Bifrost.yar#L1-L27"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "e2b64df0add316240b010db7d34d83fc9ac7001233259193e5a72b6e04aece46"
        		logic_hash = "a2ff4f1aca51e80f2b277e9171e99a80a75177d1d17d487de2eb8872832cb0d5"
        		score = 75
        		quality = 25
        		tags = "FILE, MEMORY"
        		fingerprint = "e11f6f3a847817644d40fee863e168cd2a18e8e0452482c1e652c11fe8dd769e"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$s1 = "[dump | list | askhash | describe | asktgt | asktgs | s4u | ptt | remove | asklkdcdomain]" fullword
        		$s2 = "[-] Error in parseKirbi: %s"
        		$s3 = "[-] Error in parseTGSREP: %s"
        		$s4 = "genPasswordHashPassword:Length:Enc:Username:Domain:Pretty:"
        		$s5 = "storeLKDCConfDataFriendlyName:Hostname:Password:CCacheName:"
        		$s6 = "bifrostconsole-"
        		$s7 = "-kerberoast"
        		$s8 = "asklkdcdomain"
        		$s9 = "askhash"
        
        	condition:
        		3 of them
        }
        rule ELASTIC_Macos_Backdoor_Fakeflashlxk_06Fd8071 : FILE MEMORY {
            meta:
        		description = "Detects Macos Backdoor Fakeflashlxk (MacOS.Backdoor.Fakeflashlxk)"
        		author = "Elastic Security"
        		id = "06fd8071-0370-4ae8-819a-846fa0a79b3d"
        		date = "2021-11-11"
        		modified = "2022-07-22"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Backdoor_Fakeflashlxk.yar#L1-L21"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "107f844f19e638866d8249e6f735daf650168a48a322d39e39d5e36cfc1c8659"
        		logic_hash = "853d44465a472786bb48bbe1009e0ff925f79e4fd72f0eac537dd271c1ec3703"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "a0e6763428616b46536c6a4eb080bae0cc58ef27678616aa432eb43a3d9c77a1"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$s1 = "/Users/lxk/Library/Developer/Xcode/DerivedData"
        		$s2 = "Desktop/SafariFlashActivity/SafariFlashActivity/SafariFlashActivity/"
        		$s3 = "/Debug/SafariFlashActivity.build/Objects-normal/x86_64/AppDelegate.o"
        
        	condition:
        		2 of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_28B13E67 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "28b13e67-e01c-45eb-aae6-ecd02b017a44"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "0b50a38749ea8faf571169ebcfce3dfd668eaefeb9a91d25a96e6b3881e4a3e8"
        		logic_hash = "586ae19e570c51805afd3727b2e570cdb1c48344aa699e54774a708f02bc3a6f"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "1e85be4432b87214d61e675174f117e36baa8ab949701ee1d980ad5dd8454bac"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 05 A5 A3 A9 37 D2 05 13 E9 3E D6 EA 6A EC 9B DC 36 E5 76 A7 53 B3 0F 06 46 D1 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_75C8Cb4E : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "75c8cb4e-f8bd-4a2c-8a5e-8500e12a9030"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L21-L39"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "3d69912e19758958e1ebdef5e12c70c705d7911c3b9df03348c5d02dd06ebe4e"
        		logic_hash = "527fecb8460c0325c009beddd6992e0abbf8c5a05843e4cedf3b17deb4b19a1c"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "db68c315dba62f81168579aead9c5827f7bf1df4a3c2e557b920fa8fbbd6f3c2"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 EE 19 00 00 EA 80 35 E8 19 00 00 3B 80 35 E2 19 00 00 A4 80 35 DC 19 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_17B564B4 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "17b564b4-7452-473f-873f-f907b5b8ebc4"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L41-L59"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "94f6e5ee6eb3a191faaf332ea948301bbb919f4ec6725b258e4f8e07b6a7881d"
        		logic_hash = "40cd2a793c8ed51a8191ecb9b358f50dc2035d997d0f773f6049f9c272291607"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "7701fab23d59b8c0db381a1140c4e350e2ce24b8114adbdbf3c382c6d82ea531"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 D9 11 00 00 05 80 35 D3 11 00 00 2B 80 35 CD 11 00 00 F6 80 35 C7 11 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_C90C088A : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "c90c088a-abf5-4e52-a69e-5a4fd4b5cf15"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L61-L79"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "875513f4ebeb63b9e4d82fb5bff2b2dc75b69c0bfa5dd8d2895f22eaa783f372"
        		logic_hash = "c82c5c8d1e38e0d2631c5611e384eb49b58c64daeafe0cc642682e5c64686b60"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "c2300895f8ff5ae13bc0ed93653afc69b30d1d01f5ce882bd20f2b65426ecb47"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 E1 11 00 00 92 80 35 DB 11 00 00 2A 80 35 D5 11 00 00 7F 80 35 CF 11 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_3965578D : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "3965578d-3180-48e4-b5be-532e880b1df9"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L81-L99"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "d72543505e36db40e0ccbf14f4ce3853b1022a8aeadd96d173d84e068b4f68fa"
        		logic_hash = "6bd24640e0a3aa152fcd90b6975ee4fb7e99ab5f2d48d3a861bc804c526c90b6"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "e41f08618db822ba5185e5dc3f932a72e1070fbb424ff2c097cab5e58ad9e2db"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 33 2A 00 00 60 80 35 2D 2A 00 00 D0 80 35 27 2A 00 00 54 80 35 21 2A 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_00D9D0E9 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "00d9d0e9-28d8-4c32-bc6f-52008ee69b07"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L101-L119"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "73069b34e513ff1b742b03fed427dc947c22681f30cf46288a08ca545fc7d7dd"
        		logic_hash = "535831872408caa27984190d1b1b1a5954e502265925d50457e934219598dbfd"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "7dcc6b124d631767c259101f36b4bbd6b9d27b2da474d90e31447ea03a2711a6"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 8E 11 00 00 55 80 35 88 11 00 00 BC 80 35 82 11 00 00 72 80 35 7C 11 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_650B8Ff4 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "650b8ff4-6cc8-4bfc-ba01-ac9c86410ecc"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L121-L139"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "78fd2c4afd7e810d93d91811888172c4788a0a2af0b88008573ce8b6b819ae5a"
        		logic_hash = "e8a706db010e9c3d9714d5e7a376e9b2189af382a7b01db9a9e7ee947e9637bb"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "4f4691f6830684a71e7b3ab322bf6ec4638bf0035adf3177dbd0f02e54b3fd80"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 8B 11 00 00 60 80 35 85 11 00 00 12 80 35 7F 11 00 00 8C 80 35 79 11 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_C8Ad7Edd : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "c8ad7edd-4233-44ce-a4e5-96dfc3504f8a"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L141-L159"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "d4915473e1096a82afdaee405189a0d0ae961bd11a9e5e9adc420dd64cb48c24"
        		logic_hash = "be09b4bd612bb499044fe91ca4e1ab62405cf1e4d75b8e1da90e326d1c66e04f"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "c6a8a1d9951863d4277d297dd6ff8ad7b758ca2dfe16740265456bb7bb0fd7d0"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 74 11 00 00 D5 80 35 6E 11 00 00 57 80 35 68 11 00 00 4C 80 35 62 11 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_Cb7344Eb : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "cb7344eb-51e6-4f17-a5d4-eea98938945b"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L161-L179"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "53373668d8c5dc17f58768bf59fb5ab6d261a62d0950037f0605f289102e3e56"
        		logic_hash = "6b5e868dfd14e9b1cdf3caeb1216764361b28c1dd38849526baf5dbdb1020d8d"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "6041c50c9eefe9cafb8768141cd7692540f6af2cdd6e0a763b7d7e50b8586999"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 ED 09 00 00 92 80 35 E7 09 00 00 93 80 35 E1 09 00 00 16 80 35 DB 09 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_753E5738 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "753e5738-0c72-4178-9396-d1950e868104"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L181-L199"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "42aeea232b28724d1fa6e30b1aeb8f8b8c22e1bc8afd1bbb4f90e445e31bdfe9"
        		logic_hash = "7a6907b51c793e4182c1606eab6f2bcb71f0350a34aef93fa3f3a9f1a49961ba"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "c0a41a8bc7fbf994d3f5a5d6c836db3596b1401b0e209a081354af2190fcb3c2"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 9A 11 00 00 96 80 35 94 11 00 00 68 80 35 8E 11 00 00 38 80 35 88 11 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Bundlore_7B9F0C28 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
        		author = "Elastic Security"
        		id = "7b9f0c28-181d-4fdc-8a57-467d5105129a"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Bundlore.yar#L201-L219"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "fc4da125fed359d3e1740dafaa06f4db1ffc91dbf22fd5e7993acf8597c4c283"
        		logic_hash = "32abbb76c866e3a555ee6a9c39f62a0712f641959b66068abfb4379baa9a9da9"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "dde16fdd37a16fa4dae24324283cd4b36ed2eb78f486cedd1a6c7bef7cde7370"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 35 B6 15 00 00 81 80 35 B0 15 00 00 14 80 35 AA 15 00 00 BC 80 35 A4 15 00 00 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Amcleaner_445Bb666 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Amcleaner (MacOS.Trojan.Amcleaner)"
        		author = "Elastic Security"
        		id = "445bb666-1707-4ad9-a409-4a21de352957"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Amcleaner.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
        		logic_hash = "664829ff761186ec8f3055531b5490b7516756b0aa9d0183d4c17240a5ca44c4"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "355c7298a4148be3b80fd841b483421bde28085c21c00d5e4a42949fd8026f5b"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 10 A0 5B 15 57 A8 8B 17 02 F9 A8 9B E8 D5 8C 96 A7 48 42 91 E5 EC 3D C8 AC 52 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Amcleaner_A91D3907 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Amcleaner (MacOS.Trojan.Amcleaner)"
        		author = "Elastic Security"
        		id = "a91d3907-5e24-46c0-90ef-ed7f46ad8792"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Amcleaner.yar#L21-L39"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "dc9c700f3f6a03ecb6e3f2801d4269599c32abce7bc5e6a1b7e6a64b0e025f58"
        		logic_hash = "e61ceea117acf444a6b137b93d7c335c6eb8a7e13a567177ec4ea44bf64fd5c6"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "c020567fde77a72d27c9c06f6ebb103f910321cc7a1c3b227e0965b079085b49"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 40 22 4E 53 49 6D 61 67 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6A 76 64 69 5A }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Amcleaner_8Ce3Fea8 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Amcleaner (MacOS.Trojan.Amcleaner)"
        		author = "Elastic Security"
        		id = "8ce3fea8-3cc7-4c59-b07c-a6dda0bb6b85"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Amcleaner.yar#L41-L59"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
        		logic_hash = "08c4b5b4afefbf1ee207525f9b28bc7eed7b55cb07f8576fddfa0bbe95002769"
        		score = 75
        		quality = 73
        		tags = "FILE, MEMORY"
        		fingerprint = "e156d3c7a55cae84481df644569d1c5760e016ddcc7fd05d0f88fa8f9f9ffdae"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = { 54 40 22 4E 53 54 61 62 6C 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6B 54 70 51 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Hloader_A3945Baf : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Hloader (MacOS.Trojan.HLoader)"
        		author = "Elastic Security"
        		id = "a3945baf-4708-4a0b-8a9b-1a5448ee4bc7"
        		date = "2023-10-23"
        		modified = "2023-10-23"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_HLoader.yar#L1-L21"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "2360a69e5fd7217e977123c81d3dbb60bf4763a9dae6949bc1900234f7762df1"
        		logic_hash = "0383485b6bbcdae210a6c949f6796023b2f7ec3f1edbd2116207fc2b75a67849"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "a48ec79f07a6a53611b1d1e8fe938513ec0ea19344126e07331b48b028cb877e"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$seq_main = { 74 ?? 49 89 C7 48 89 D8 4C 89 FF E8 ?? ?? ?? ?? 48 89 DF 31 F6 BA ?? ?? ?? ?? 4C 89 65 ?? 4D 89 F4 4C 89 F1 4C 8B 75 ?? 41 FF 56 ?? }
        		$seq_exec = { 48 B8 00 00 00 00 00 00 00 E0 48 89 45 ?? 4C 8D 6D ?? BF 11 00 00 00 E8 ?? ?? ?? ?? 0F 10 45 ?? 0F 11 45 ?? 48 BF 65 78 65 63 46 69 6C 65 48 BE 20 65 72 72 6F 72 20 EF }
        		$seq_rename = { 41 89 DE 84 DB 74 ?? 48 8B 7D ?? FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? }
        
        	condition:
        		2 of ($seq*)
        }
        rule ELASTIC_Macos_Trojan_Metasploit_6Cab0Ec0 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Metasploit (MacOS.Trojan.Metasploit)"
        		author = "Elastic Security"
        		id = "6cab0ec0-0ac5-4f43-8a10-1f46822a152b"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L1-L19"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        		logic_hash = "c19fe812b74b034bfb42c0e2ee552d879ed038e054c5870b85e7e610d3184198"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "e13c605d8f16b2b2e65c717a4716c25b3adaec069926385aff88b37e3db6e767"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a = "mettlesploit! " ascii fullword
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_293Bfea9 : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Metasploit (MacOS.Trojan.Metasploit)"
        		author = "Elastic Security"
        		id = "293bfea9-c5cf-4711-bec0-17a02ddae6f2"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L21-L42"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        		logic_hash = "b8bd0d034a6306f99333723d77724ae53c1a189dad3fad7417f2d2fde214c24a"
        		score = 75
        		quality = 71
        		tags = "FILE, MEMORY"
        		fingerprint = "d47e8083268190465124585412aaa2b30da126083f26f3eda4620682afd1d66e"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = "_webcam_get_frame" ascii fullword
        		$a2 = "_get_process_info" ascii fullword
        		$a3 = "process_new: got %zd byte executable to run in memory" ascii fullword
        		$a4 = "Dumping cert info:" ascii fullword
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_448Fa81D : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Metasploit (MacOS.Trojan.Metasploit)"
        		author = "Elastic Security"
        		id = "448fa81d-14c7-479b-8d1e-c245ee261ef6"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L44-L64"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        		logic_hash = "ab0608920b9f632bad99e1358f21a88bc6048f46fca21a488a1a10b7ef1e42ae"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "ff040211f664f3f35cd4f4da0e5eb607ae3e490aae75ee97a8fb3cb0b08ecc1f"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = "/Users/vagrant/mettle/mettle/src/process.c" ascii fullword
        		$a2 = "/Users/vagrant/mettle/mettle/src/c2_http.c" ascii fullword
        		$a3 = "/Users/vagrant/mettle/mettle/src/mettle.c" ascii fullword
        
        	condition:
        		any of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_768Df39D : FILE MEMORY {
            meta:
        		description = "Byte sequence based on Metasploit shell_reverse_tcp.rb"
        		author = "Elastic Security"
        		id = "768df39d-7ee9-454e-82f8-5c7bd733c61a"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_reverse_tcp.rb"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L66-L85"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "140ba93d57b27325f66b36132ecaab205663e3e582818baf377e050802c8d152"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "d45230c1111bda417228e193c8657d2318b1d2cddfbd01c5c6f2ea1d0be27a46"
        		threat_name = "MacOS.Trojan.Metasploit"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = { FF 4F E8 79 F6 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_7Ce0B709 : FILE MEMORY {
            meta:
        		description = "Byte sequence based on Metasploit shell_bind_tcp.rb"
        		author = "Elastic Security"
        		id = "7ce0b709-1d96-407c-8eca-6af64e5bdeef"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_bind_tcp.rb"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L87-L106"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "56fc05ece464d562ff6e56247756454c940c07b03c4a4c783b2bae4d5807247a"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "3eb7f78d2671e16c16a6d9783995ebb32e748612d32ed4f2442e9f9c1efc1698"
        		threat_name = "MacOS.Trojan.Metasploit"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = { FF 4F E4 79 F6 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_F11Ccdac : FILE MEMORY {
            meta:
        		description = "Byte sequence based on Metasploit shell_find_port.rb"
        		author = "Elastic Security"
        		id = "f11ccdac-be75-4ba8-800a-179297a40792"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_find_port.rb"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L108-L127"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "fcf578d3e98b591b33cb6f4bec1b9e92a7e1a88f0b56f3c501f9089d2094289c"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "fbc1a5b77ed485706ae38f996cd086253ea1d43d963cb497446e5b0f3d0f3f11"
        		threat_name = "MacOS.Trojan.Metasploit"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = { 50 6A 1F 58 CD 80 66 81 7F 02 04 D2 75 EE 50 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_D9B16F4C : FILE MEMORY {
            meta:
        		description = "Byte sequence based on Metasploit vforkshell_bind_tcp.rb"
        		author = "Elastic Security"
        		id = "d9b16f4c-8cc9-42ce-95fa-8db06df9d582"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_bind_tcp.rb"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L129-L148"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "8e082878fb52f6314ec8c725dd279447ee8a0fc403c47ffd997712adb496e7c3"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "cf5cfc372008ae98a0958722a7b23f576d6be3b5b07214d21594a48a87d92fca"
        		threat_name = "MacOS.Trojan.Metasploit"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7E 00 00 00 89 C6 52 52 52 68 00 02 34 12 89 E3 6A }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_2992B917 : FILE MEMORY {
            meta:
        		description = "Byte sequence based on Metasploit vforkshell_reverse_tcp.rb"
        		author = "Elastic Security"
        		id = "2992b917-32bd-4fd8-8221-0d061239673d"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_reverse_tcp.rb"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L150-L169"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "10056ffb719092f83ad236a63ef6fa1f40568e500c042bd737575997bb67a8ec"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "055129bc7931d0334928be00134c109ab36825997b2877958e0ca9006b55575e"
        		threat_name = "MacOS.Trojan.Metasploit"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 6D 89 C7 52 52 68 7F 00 00 01 68 00 02 34 12 89 E3 6A }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_27D409F1 : FILE MEMORY {
            meta:
        		description = "Byte sequence based on Metasploit x64 shell_bind_tcp.rb"
        		author = "Elastic Security"
        		id = "27d409f1-80fd-4d07-815a-4741c48e0bf6"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x64/shell_bind_tcp.rb"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L171-L190"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "b757e0ab6665a3e4846c6bbe4386e9d9a730ece00a2453933ce771aec2dd716e"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "43be41784449fc414c3e3bc7f4ca5827190fa10ac4cdd8500517e2aa6cce2a56"
        		threat_name = "MacOS.Trojan.Metasploit"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = { B8 61 00 00 02 6A 02 5F 6A 01 5E 48 31 D2 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_65A2394B : FILE MEMORY {
            meta:
        		description = "Byte sequence based on Metasploit stages vforkshell.rb"
        		author = "Elastic Security"
        		id = "65a2394b-0e66-4cb5-b6aa-3909120f0a94"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stages/osx/x86/vforkshell.rb"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L192-L211"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "f01f671b0bf9fa53aa3383c88ba871742f0e55dbdae4278f440ed29f35eb1ca1"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "082da76eb8da9315d495b79466366367f19170f93c0a29966858cb92145e38d7"
        		threat_name = "MacOS.Trojan.Metasploit"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = { 31 DB 83 EB 01 43 53 57 53 B0 5A CD 80 72 43 83 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_C7B7A90B : FILE MEMORY {
            meta:
        		description = "Byte sequence based on Metasploit stager reverse_tcp.rb"
        		author = "Elastic Security"
        		id = "c7b7a90b-aaf2-482d-bb95-dee20a75379e"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/reverse_tcp.rb"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L213-L232"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "d4b1f01bf8434dd69188d2ad0b376fad3a4d9c94ebe74d40f05019baf95b5496"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "c4b2711417f5616ca462149882a7f33ce53dd1b8947be62fe0b818c51e4f4b2f"
        		threat_name = "MacOS.Trojan.Metasploit"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_4Bd6Aaca : FILE MEMORY {
            meta:
        		description = "Byte sequence based on Metasploit stager x86 bind_tcp.rb"
        		author = "Elastic Security"
        		id = "4bd6aaca-f519-4d20-b3af-d376e0322a7e"
        		date = "2021-09-30"
        		modified = "2021-10-25"
        		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/bind_tcp.rb"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L234-L253"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		logic_hash = "a3de610ced90679f6fa0dcdf7890a64369c774839ea30018a7ef6fe9289d3d17"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "f4957b565d2b86c79281a0d3b2515b9a0c72f9c9c7b03dae18a3619d7e2fc3dc"
        		threat_name = "MacOS.Trojan.Metasploit"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7D }
        
        	condition:
        		all of them
        }
        rule ELASTIC_Macos_Trojan_Metasploit_5E5B685F : FILE MEMORY {
            meta:
        		description = "Detects Macos Trojan Metasploit (MacOS.Trojan.Metasploit)"
        		author = "Elastic Security"
        		id = "5e5b685f-1b6b-4102-b54d-91318e418c6c"
        		date = "2021-10-05"
        		modified = "2021-10-25"
        		reference = "https://github.com/elastic/protections-artifacts/"
        		source_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/yara/rules/MacOS_Trojan_Metasploit.yar#L255-L273"
        		license_url = "https://github.com/elastic/protections-artifacts//blob/efd00abcfc634000adf2f245f5bebfb9ea7e067a/LICENSE.txt"
        		hash = "cdf0a3c07ef1479b53d49b8f22a9f93adcedeea3b869ef954cc043e54f65c3d0"
        		logic_hash = "003fb4f079b125f37899a2b3cb62d80edd5b3e5ccbed5bc1ea514a4a173d329d"
        		score = 75
        		quality = 75
        		tags = "FILE, MEMORY"
        		fingerprint = "52c41d4fc4d195e702523dd2b65e4078dd967f9c4e4b1c081bc04d88c9e4804f"
        		severity = 100
        		arch_context = "x86"
        		scan_context = "file, memory"
        		license = "Elastic License v2"
        		os = "macos"
        
        	strings:
        		$a1 = { 00 00 F4 90 90 90 90 55 48 89 E5 48 81 EC 60 20 00 00 89 F8 48 8B 0D 74 23 00 }
        
        	condition:
        		all of them
        }
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
        		BINARYALERT_Macho_PRIVATE and 2 of ($a*) or all of ($b*)
        }
        rule VOLEXITY_Apt_Malware_Macos_Vpnclient_Cc_Oct23 : CHARMINGCYPRESS FILE MEMORY {
            meta:
        		description = "Detection for fake macOS VPN client used by CharmingCypress."
        		author = "threatintel@volexity.com"
        		id = "e0957936-dc6e-5de6-bb23-d0ef61655029"
        		date = "2023-10-17"
        		modified = "2023-10-27"
        		reference = "TIB-20231027"
        		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2024/2024-02-13 CharmingCypress/rules.yar#L236-L261"
        		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
        		logic_hash = "da5e9be752648b072a9aaeed884b8e1729a14841e33ed6633a0aaae1f11bd139"
        		score = 75
        		quality = 80
        		tags = "CHARMINGCYPRESS, FILE, MEMORY"
        		hash1 = "11f0e38d9cf6e78f32fb2d3376badd47189b5c4456937cf382b8a574dc0d262d"
        		os = "darwin,linux"
        		os_arch = "all"
        		parent_hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
        		scan_context = "file,memory"
        		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        		rule_id = 9770
        		version = 3
        
        	strings:
        		$s1 = "networksetup -setsocksfirewallproxystate wi-fi off" ascii
        		$s2 = "networksetup -setsocksfirewallproxy wi-fi ___serverAdd___ ___portNum___; networksetup -setsocksfirewallproxystate wi-fi on" ascii
        		$s3 = "New file imported successfully." ascii
        		$s4 = "Error in importing the File." ascii
        
        	condition:
        		2 of ($s*)
        }
        rule VOLEXITY_Hacktool_Py_Pysoxy : FILE MEMORY {
            meta:
        		description = "SOCKS5 proxy tool used to relay connections."
        		author = "threatintel@volexity.com"
        		id = "88094b55-784d-5245-9c40-b1eebf0e6e72"
        		date = "2024-01-09"
        		modified = "2024-01-09"
        		reference = "TIB-20240109"
        		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L85-L111"
        		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
        		logic_hash = "f73e9d3c2f64c013218469209f3b69fc868efafc151a7de979dde089bfdb24b2"
        		score = 75
        		quality = 80
        		tags = "FILE, MEMORY"
        		hash1 = "e192932d834292478c9b1032543c53edfc2b252fdf7e27e4c438f4b249544eeb"
        		os = "all"
        		os_arch = "all"
        		scan_context = "file,memory"
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
        rule VOLEXITY_Malware_Golang_Discordc2_Bmdyy_1 : FILE MEMORY {
            meta:
        		description = "Detects a opensource malware available on github using strings in the ELF. DISGOMOJI used by UTA0137 is based on this malware."
        		author = "threatintel@volexity.com"
        		id = "6816d264-4311-5e90-948b-2e27cdf0b720"
        		date = "2024-03-28"
        		modified = "2024-03-28"
        		reference = "TIB-20240229"
        		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L215-L241"
        		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
        		logic_hash = "22b3e5109d0738552fbc310344b2651ab3297e324bc883d5332c1e8a7a1df29b"
        		score = 75
        		quality = 80
        		tags = "FILE, MEMORY"
        		hash1 = "de32e96d1f151cc787841c12fad88d0a2276a93d202fc19f93631462512fffaf"
        		os = "all"
        		os_arch = "all"
        		scan_context = "file,memory"
        		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        		rule_id = 10390
        		version = 2
        
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
        		description = "Detects a opensource malware available on github using strings in the ELF. DISGOMOJI used by UTA0137 is based on this malware."
        		author = "threatintel@volexity.com"
        		id = "1ddbf476-ba2d-5cbb-ad95-38e0ae8db71b"
        		date = "2024-02-22"
        		modified = "2024-03-28"
        		reference = "https://github.com/bmdyy/discord-c2"
        		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L243-L265"
        		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
        		logic_hash = "38b860a43b9937351f74b01983888f18ad101cbe66560feb7455d46b713eba0f"
        		score = 75
        		quality = 80
        		tags = "FILE, MEMORY"
        		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
        		os = "all"
        		os_arch = "all"
        		scan_context = "file,memory"
        		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        		rule_id = 10264
        		version = 10
        
        	strings:
        		$s1 = "**IP**: %s\n**User**: %s\n**Hostname**: %s\n**OS**: %s\n**CWD**" wide ascii
        
        	condition:
        		$s1
        }
        rule VOLEXITY_Susp_Any_Jarischf_User_Path : FILE MEMORY {
            meta:
        		description = "Detects paths embedded in samples in released projects written by Ferdinand Jarisch, a pentester in AISEC. These tools are sometimes used by attackers in real world intrusions."
        		author = "threatintel@volexity.com"
        		id = "062a6fdb-c516-5643-9c7c-deff32eeb95e"
        		date = "2024-04-10"
        		modified = "2024-04-12"
        		reference = "TIB-20240412"
        		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L57-L78"
        		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
        		logic_hash = "574d5b1fadb91c39251600e7d73d4993d4b16565bd1427a0e8d6ed4e7905ab54"
        		score = 50
        		quality = 80
        		tags = "FILE, MEMORY"
        		hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
        		os = "all"
        		os_arch = "all"
        		scan_context = "file,memory"
        		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        		rule_id = 10424
        		version = 4
        
        	strings:
        		$proj_1 = "/home/jarischf/"
        
        	condition:
        		any of ($proj_*)
        }
        rule VOLEXITY_Hacktool_Golang_Reversessh_Fahrj : FILE MEMORY {
            meta:
        		description = "Detects a reverse SSH utility available on GitHub. Attackers may use this tool or similar tools in post-exploitation activity."
        		author = "threatintel@volexity.com"
        		id = "332e323f-cb16-5aa2-8b66-f3d6d50d94f2"
        		date = "2024-04-10"
        		modified = "2024-04-12"
        		reference = "TIB-20240412"
        		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L79-L112"
        		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
        		logic_hash = "38b40cc7fc1e601da2c7a825f1c2eff209093875a5829ddd2f4c5ad438d660f8"
        		score = 75
        		quality = 80
        		tags = "FILE, MEMORY"
        		hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
        		os = "all"
        		os_arch = "all"
        		scan_context = "file,memory"
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
        		any of ($proj_*) or 4 of ($fun_*)
        }
