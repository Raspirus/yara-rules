rule CAPE_Tclient : FILE
{
	meta:
		description = "TClient Payload"
		author = "kevoreilly"
		id = "38c9ea20-9d91-5fb0-8b3b-170538ad7ea8"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/TClient.yar#L1-L11"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "6edcd01e4722b367723ed77d9596877d16ee35dc4c160885d125f83e45cee24d"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "TClient Payload"

	strings:
		$code1 = {41 0F B6 00 4D 8D 40 01 34 01 8B D7 83 E2 07 0F BE C8 FF C7 41 0F BE 04 91 0F AF C1 41 88 40 FF 81 FF 80 03 00 00 7C D8}

	condition:
		uint16(0)==0x5A4D and any of ($code*)
}