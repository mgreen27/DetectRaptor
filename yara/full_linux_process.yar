rule HARFANGLAB_Nhas_Reverse_Shell_Elf_Inmem_Large {
    meta:
		description = "Matches packed NHAS reverse_ssh ELF samples in-memory during execution"
		author = "HarfangLab"
		id = "cd6f7b81-b8df-5e2b-9da6-981d1f62c131"
		date = "2024-09-24"
		modified = "2025-10-21"
		reference = "TRR250201"
		source_url = "https://github.com/HarfangLab/iocs/blob/1770ec1114cc8c83eea7d0ab8f9f29c267b11a2d/hl_public_reports_master.yar#L295-L312"
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
