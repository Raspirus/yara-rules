
rule CAPE_Dreambot : FILE
{
	meta:
		description = "Dreambot Payload"
		author = "kevoreilly"
		id = "675c2fea-fe48-5afd-9fa1-de919134892f"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Dreambot.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "29c6d648d5d38667c5824c2d20a83a20448c2ae6054ddddb2b2b7f8bdb69f74b"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Dreambot Payload"

	strings:
		$a1 = {53 56 33 F6 33 DB C1 6C 24 0C 02 74 2F 8B 02 85 C0 75 11 83 7C 24 0C 02 76 0A 39 42 04 75 05 39 42 08 74 18 43 8A CB D3 C0 33 C6 33 44 24 10 8B F0 89 32 83 C2 04 FF 4C 24 0C 75 D1 5E 5B C2 08 00}
		$a2 = {53 33 C9 33 DB C1 6C 24 08 02 74 22 56 8B 02 85 C0 8B F0 74 18 33 C1 33 44 24 10 43 8A CB D3 C8 8B CE 89 02 83 C2 04 FF 4C 24 0C 75 E0 5E 5B C2 08 00}
		$b1 = "Oct  5 2016"
		$b2 = ".bss"

	condition:
		uint16(0)==0x5A4D and (1 of ($a*)) and ( all of ($b*))
}