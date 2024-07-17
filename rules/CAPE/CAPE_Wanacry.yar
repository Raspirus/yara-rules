rule CAPE_Wanacry : FILE
{
	meta:
		description = "WanaCry Payload"
		author = "kevoreilly"
		id = "a6525e0f-fccd-5542-9be8-e42d708fe502"
		date = "2022-06-09"
		modified = "2022-06-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/WanaCry.yar#L1-L16"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "16d5e39f043d27bbf22f8f21e13971b7e0709b07e44746dd157d11ee4cc51944"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "WanaCry Payload"

	strings:
		$exename = "@WanaDecryptor@.exe"
		$res = "%08X.res"
		$pky = "%08X.pky"
		$eky = "%08X.eky"
		$taskstart = {8B 35 58 71 00 10 53 68 C0 D8 00 10 68 F0 DC 00 10 FF D6 83 C4 0C 53 68 B4 D8 00 10 68 24 DD 00 10 FF D6 83 C4 0C 53 68 A8 D8 00 10 68 58 DD 00 10 FF D6 53}

	condition:
		uint16(0)==0x5A4D and all of them
}