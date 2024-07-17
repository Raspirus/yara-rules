rule CAPE_Pikabotloader : FILE
{
	meta:
		description = "Pikabot Loader"
		author = "kevoreilly"
		id = "e2c89cdd-0cdb-5367-8aae-2fe685eff972"
		date = "2024-03-13"
		modified = "2024-03-13"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/PikaBot.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "7e5f1f2911545ee6bd36b54f2627fbdec1b957f4b91df901dd1c6cbd4dff0231"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "PikaBot Loader"

	strings:
		$indirect = {31 C0 64 8B 0D C0 00 00 00 85 C9 74 01 40 50 8D 54 24 ?? E8 [4] A3 [4] 8B 25 [4] A1}
		$sysenter1 = {89 44 24 08 8D 85 ?? FC FF FF C7 44 24 04 FF FF 1F 00 89 04 24 E8}
		$sysenter2 = {C7 44 24 0C 00 00 00 02 C7 44 24 08 00 00 00 02 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8}

	condition:
		uint16(0)==0x5A4D and 2 of them
}