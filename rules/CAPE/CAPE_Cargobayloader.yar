rule CAPE_Cargobayloader : FILE
{
	meta:
		description = "CargoBay Loader"
		author = "kevoreilly"
		id = "5b347863-0bea-55d2-aaf3-b3d6e604be89"
		date = "2023-02-20"
		modified = "2023-02-20"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/CargoBayLoader.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		hash = "75e975031371741498c5ba310882258c23b39310bd258239277708382bdbee9c"
		logic_hash = "1d5c4ca79f97e1fac358189a8c6530be12506974fc2fb42f63b0b621536a45c9"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "CargoBay Loader"

	strings:
		$jmp1 = {40 42 0F 00 0F 82 [2] 00 00 48 8D 15 [4] BF 04 00 00 00 41 B8 04 00 00 00 4C 8D [3] 4C 89 F1 E8}
		$jmp2 = {84 DB 0F 85 [2] 00 00 48 8D 15 [4] 41 BE 03 00 00 00 41 B8 03 00 00 00 4C 8D 7C [2] 4C 89 F9 E8}

	condition:
		uint16(0)==0x5A4D and all of them
}