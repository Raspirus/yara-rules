rule CAPE_Doomedloader : FILE
{
	meta:
		description = "No description has been set in the source file - CAPE"
		author = "kevoreilly"
		id = "88436e71-360e-5719-989f-24e71591ebe0"
		date = "2024-05-09"
		modified = "2024-05-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/DoomedLoader.yar#L1-L12"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "54a5962ef49ebf987908c4ea1559788f7c96a7e4ea61d2973636e998a0239c77"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "DoomedLoader Payload"
		packed = "914b1b3180e7ec1980d0bafe6fa36daade752bb26aec572399d2f59436eaa635"

	strings:
		$anti = {48 8B 4C 24 ?? E8 [4] 84 C0 B8 [4] 41 0F 45 C6 EB}
		$syscall = {49 89 CA 8B 44 24 08 FF 64 24 10}

	condition:
		uint16(0)==0x5A4D and all of them
}