rule CAPE_Zeuspanda : FILE
{
	meta:
		description = "ZeusPanda Payload"
		author = "kevoreilly"
		id = "7891c021-6687-5457-b9e1-0beb0472647c"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/ZeusPanda.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "43d8a56cae9fd23c053f6956851734d3270b46a906236854502c136e3bb1e761"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "ZeusPanda Payload"

	strings:
		$code1 = {8B 01 57 55 55 55 55 55 55 53 51 FF 50 0C 85 C0 78 E? 55 55 6A 03 6A 03 55 55 6A 0A FF 37}
		$code2 = {8D 85 B0 FD FF FF 50 68 ?? ?? ?? ?? 8D 85 90 FA FF FF 68 0E 01 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 7E ?? 68 04 01 00 00 8D 85 B0 FD FF FF}

	condition:
		uint16(0)==0x5A4D and all of them
}