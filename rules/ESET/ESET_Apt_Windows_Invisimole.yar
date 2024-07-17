rule ESET_Apt_Windows_Invisimole : FILE
{
	meta:
		description = "InvisiMole magic values, keys and strings"
		author = "ESET Research"
		id = "4d48996b-9792-57ba-a302-349220323712"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/invisimole/invisimole.yar#L215-L255"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "7a2cff9febe77d718089ba4e1a33f3487594588892e418cec685bf22b156fa2b"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "CryptProtectData"
		$s2 = "CryptUnprotectData"
		$s3 = {9E 01 3A AD}
		$s4 = "GET /getversion2a/%d%.2X%.2X/U%sN HTTP/1.1"
		$s5 = "PULSAR_LOADER.dll"
		$check_magic_old_32 = {3? F9 FF D0 DE}
		$check_magic_old_64 = {3? 64 FF D0 DE}
		$check_magic_new_32 = {81 3? 86 DA 11 CE}
		$check_magic_new_64 = {81 3? 64 DA 11 CE}

	condition:
		(( uint16(0)==0x5A4D) or ESET_Invisimole_Blob_PRIVATE) and ( any of ($check_magic*)) and (2 of ($s*))
}