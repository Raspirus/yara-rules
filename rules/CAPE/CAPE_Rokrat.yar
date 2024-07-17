rule CAPE_Rokrat : FILE
{
	meta:
		description = "RokRat Payload"
		author = "kevoreilly"
		id = "12e05b90-9771-5901-ae82-9fd2ea6263e7"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/RokRat.yar#L1-L12"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "2aaa7de7ccd59e0da690f4bc0c7deaacf61314d61f8d2aa3ce6f6892f50612ec"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "RokRat Payload"

	strings:
		$code1 = {8B 57 04 8D 7F 04 33 57 FC 81 E2 FF FF FF 7F 33 57 FC 8B C2 24 01 0F B6 C0 F7 D8 1B C0 D1 EA 25 DF B0 08 99 33 87 30 06 00 00 33 C2 89 87 3C F6 FF FF 83 E9 01 75 C9}
		$string1 = "/pho_%s_%d.jpg" wide

	condition:
		uint16(0)==0x5A4D and ( any of ($code*)) and ( any of ($string*))
}