rule CAPE_Sedreco : FILE
{
	meta:
		description = "Sedreco encrypt function entry"
		author = "kevoreilly"
		id = "5b9ee4af-50a4-597c-8fa5-f2094c312d23"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Sedreco.yar#L1-L15"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "f735549606917f59a19157e604e54766e4456bc5d46e94cae3e0a3c18b52a7ca"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Sedreco Payload"

	strings:
		$encrypt1 = {55 8B EC 83 EC 2C 53 56 8B F2 57 8B 7D 08 B8 AB AA AA AA}
		$encrypt2 = {55 8B EC 83 EC 20 8B 4D 10 B8 AB AA AA AA}
		$encrypt64_1 = {48 89 4C 24 08 53 55 56 57 41 54 41 56 48 83 EC 18 45 8D 34 10 48 8B E9 B8 AB AA AA AA 4D 8B E1 44 89 44 24 60 41 F7 E0 8B F2 B8 AB AA AA AA}

	condition:
		uint16(0)==0x5A4D and $encrypt1 or $encrypt2 or $encrypt64_1
}