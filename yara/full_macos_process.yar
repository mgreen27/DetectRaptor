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
