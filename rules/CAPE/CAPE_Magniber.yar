rule CAPE_Magniber : FILE
{
	meta:
		description = "Magniber Payload"
		author = "kevoreilly"
		id = "a704914f-2aa2-537d-975d-f8c23427951f"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Magniber.yar#L1-L11"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "1875754bdf98c1886f31f6c6e29992a98180f74d8fa168ae391e2c660d760618"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Magniber Payload"

	strings:
		$a1 = {8B 55 FC 83 C2 01 89 55 FC 8B 45 FC 3B 45 08 7D 45 6A 01 6A 00 E8 26 FF FF FF 83 C4 08 89 45 F4 83 7D F4 00 75 18 6A 7A 6A 61 E8 11 FF FF FF 83 C4 08 8B 4D FC 8B 55 F8 66 89 04 4A EB 16}

	condition:
		uint16(0)==0x5A4D and ( all of ($a*))
}