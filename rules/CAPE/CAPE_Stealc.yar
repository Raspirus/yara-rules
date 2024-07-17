rule CAPE_Stealc : FILE
{
	meta:
		description = "Stealc Payload"
		author = "kevoreilly"
		id = "44a00d4b-0053-5b3d-baa4-b666f7182ba0"
		date = "2024-02-16"
		modified = "2024-02-16"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Stealc.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
		logic_hash = "90a3a72f53d0c020f1568d7bbf183ee4f76ec3f4706d2331bcbc4e631bf6399d"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Stealc Payload"

	strings:
		$nugget1 = {68 04 01 00 00 6A 00 FF 15 [4] 50 FF 15 [4] 8B F?}
		$nugget2 = {64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 89 45 FC}

	condition:
		uint16(0)==0x5A4D and all of them
}