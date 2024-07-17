
rule CAPE_Amadey : FILE
{
	meta:
		description = "Amadey Payload"
		author = "kevoreilly"
		id = "b9d81aa8-5504-5b71-86c7-8c00d75479ad"
		date = "2023-09-04"
		modified = "2023-09-04"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Amadey.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		hash = "988258716d5296c1323303e8fe4efd7f4642c87bfdbe970fe9a3bb3f410f70a4"
		logic_hash = "38f710b422a3644c9f0f3e80ad9ff28ef02050368c651a6cc2ce8b152b67bf48"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Amadey Payload"

	strings:
		$decode1 = {8B D1 B8 FF FF FF 7F D1 EA 2B C2 3B C8 76 07 BB FF FF FF 7F EB 08 8D 04 0A 3B D8 0F 42 D8}
		$decode2 = {33 D2 8B 4D ?? 8B C7 F7 F6 8A 84 3B [4] 2A 44 0A 01 88 87 [4] 47 8B 45 ?? 8D 50 01}
		$decode3 = {8A 04 02 88 04 0F 41 8B 7D ?? 8D 42 01 3B CB 7C}

	condition:
		uint16(0)==0x5A4D and 2 of them
}