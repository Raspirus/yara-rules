
rule CAPE_Pik23 : FILE
{
	meta:
		description = "PikaBot Payload February 2023"
		author = "kevoreilly"
		id = "fc804c63-fc6c-5b26-92b1-aa5d2fbc4917"
		date = "2024-03-13"
		modified = "2024-03-13"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/PikaBot.yar#L30-L44"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		hash = "59f42ecde152f78731e54ea27e761bba748c9309a6ad1c2fd17f0e8b90f8aed1"
		logic_hash = "71a71df2f2a075294941c54eed06cafaaa4d3294e45b3a0098c1cffddd0438bc"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "PikaBot Payload"

	strings:
		$rdtsc = {89 55 FC 89 45 F8 0F 31 89 55 F4 89 45 FC 33 C0 B8 05 00 00 00 C1 E8 02 2B C3 3B C1 0F 31 89 55 F0 89 45 F8 8B 44 8D}
		$int2d = {B8 00 00 00 00 CD 2D 90 C3 CC CC CC CC CC CC CC}
		$subsys = {64 A1 30 00 00 00 8B 40 18 C3}
		$rijndael = {EB 0F 0F B6 04 3? FE C? 8A 80 [4] 88 04 3? 0F B6 [3] 7C EA 5? 5? C9 C3}

	condition:
		uint16(0)==0x5A4D and 3 of them
}