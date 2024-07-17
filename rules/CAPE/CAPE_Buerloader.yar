
rule CAPE_Buerloader : FILE
{
	meta:
		description = "No description has been set in the source file - CAPE"
		author = "kevoreilly & Rony (@r0ny_123)"
		id = "95a9b4d7-db1e-50cd-bc08-01e4e4fd6dc4"
		date = "2022-05-31"
		modified = "2022-05-31"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/BuerLoader.yar#L1-L12"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "05c1f008f0a2bb8232867977fb23a5ae8312f10f0637c6265561052596319c29"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "BuerLoader Payload"

	strings:
		$trap = {0F 31 89 45 ?? 6A 00 8D 45 ?? 8B CB 50 E8 [4] 0F 31}
		$decode = {8A 0E 84 C9 74 0E 8B D0 2A 0F 46 88 0A 42 8A 0E 84 C9 75 F4 5F 5E 5D C2 04 00}
		$op = {33 C0 85 D2 7E 1? 3B C7 7D [0-15] 40 3B C2 7C ?? EB 02}

	condition:
		uint16(0)==0x5A4D and 2 of them
}