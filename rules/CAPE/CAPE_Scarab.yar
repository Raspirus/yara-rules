rule CAPE_Scarab : FILE
{
	meta:
		description = "Scarab Payload"
		author = "kevoreilly"
		id = "2ba8ae50-1e56-5773-aaea-058161b59c78"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Scarab.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "0d8fa7ab4c8e5699f17f9e9444e85a42563a840a8e7ee9eda54add3a6845d1c6"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Scarab Payload"

	strings:
		$crypt1 = {8B D8 32 1A 0F B6 DB 8B 1C 9F C1 E8 08 33 D8 8B C3 42 8B D8 32 1A 0F B6 DB 8B 1C 9F C1 E8 08 33 D8 8B C3 42 8B D8 32 1A 0F B6 DB 8B 1C 9F C1 E8 08}
		$crypt2 = {8B 4C 82 0C 8B D9 C1 E3 18 C1 E9 08 0B D9 8B CB 0F B6 D9 8B 1C 9D AC 0C 43 00 89 5C 24 04 8B D9 C1 EB 08 0F B6 DB 8B 34 9D AC 0C 43 00 8B D9 C1 EB 10}
		$crypt3 = {8B 13 8B CA 81 E1 80 80 80 80 8B C1 C1 E8 07 50 8B C1 59 2B C1 25 1B 1B 1B 1B 8B CA 81 E1 7F 7F 7F 7F 03 C9 33 C1 8B C8 81 E1 80 80 80 80 8B F1 C1 EE 07}

	condition:
		uint16(0)==0x5A4D and all of them
}